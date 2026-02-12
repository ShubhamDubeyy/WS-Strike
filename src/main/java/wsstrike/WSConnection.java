package wsstrike;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * Standalone WebSocket connection for fuzzer/repeater.
 * Opens its own connection (not through Burp proxy) so we have
 * full control over sending, receiving, reconnection, etc.
 */
public class WSConnection {

    private volatile WebSocket ws;
    private volatile String url;
    private volatile String detectedProtocol = "raw";
    private final Map<String, String> headers = new ConcurrentHashMap<>();
    private final List<String> stateChain = new CopyOnWriteArrayList<>();
    private volatile String subprotocol = null;
    private volatile Consumer<String> onMessage;
    private volatile Consumer<String> onStatus;
    private volatile Consumer<byte[]> onBinaryMessage;
    private volatile boolean connected = false;
    private volatile boolean connecting = false;
    private volatile ScheduledExecutorService keepaliveExecutor;
    private volatile int socketIOPingInterval = 25000;
    private final Object connectionLock = new Object();

    // Pattern to detect CRLF injection attempts in headers
    private static final Pattern CRLF_PATTERN = Pattern.compile("[\\r\\n]");

    public WSConnection() {}

    /**
     * Validate WebSocket URL format and scheme
     */
    private static void validateUrl(String url) throws IllegalArgumentException {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be empty");
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("ws") && !scheme.equalsIgnoreCase("wss"))) {
                throw new IllegalArgumentException("URL must use ws:// or wss:// scheme");
            }
            if (uri.getHost() == null || uri.getHost().isEmpty()) {
                throw new IllegalArgumentException("URL must have a valid host");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format: " + e.getMessage());
        }
    }

    /**
     * Sanitize header value to prevent CRLF injection
     */
    private static String sanitizeHeaderValue(String value) {
        if (value == null) return "";
        // Remove any CR or LF characters to prevent header injection
        return CRLF_PATTERN.matcher(value).replaceAll("");
    }

    /**
     * Set WebSocket subprotocol (Sec-WebSocket-Protocol header)
     */
    public void setSubprotocol(String protocol) {
        this.subprotocol = sanitizeHeaderValue(protocol);
    }

    public void setOnBinaryMessage(Consumer<byte[]> handler) {
        this.onBinaryMessage = handler;
    }

    /**
     * Set headers for the HTTP upgrade request (cookies, auth tokens, etc.)
     * Headers are sanitized to prevent CRLF injection.
     */
    public void setHeaders(Map<String, String> headers) {
        this.headers.clear();
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String key = sanitizeHeaderValue(entry.getKey());
                String value = sanitizeHeaderValue(entry.getValue());
                if (!key.isEmpty()) {
                    this.headers.put(key, value);
                }
            }
        }
    }

    public void setOnMessage(Consumer<String> handler) {
        this.onMessage = handler;
    }

    public void setOnStatus(Consumer<String> handler) {
        this.onStatus = handler;
    }

    /**
     * Set the state chain — frames to replay after (re)connection.
     */
    public void setStateChain(List<String> chain) {
        this.stateChain.clear();
        this.stateChain.addAll(chain);
    }

    /**
     * Connect to the WebSocket URL.
     */
    public CompletableFuture<Boolean> connect(String url) {
        CompletableFuture<Boolean> result = new CompletableFuture<>();

        // Validate URL before attempting connection
        try {
            validateUrl(url);
        } catch (IllegalArgumentException e) {
            status("Invalid URL: " + e.getMessage());
            result.completeExceptionally(e);
            return result;
        }

        synchronized (connectionLock) {
            if (connecting) {
                result.completeExceptionally(new IllegalStateException("Connection already in progress"));
                return result;
            }
            connecting = true;
        }

        this.url = url;

        try {
            // Trust all certs (pentest tool — we're MITM'ing ourselves)
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String type) {}
                public void checkServerTrusted(X509Certificate[] certs, String type) {}
            }}, new java.security.SecureRandom());

            HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10));

            HttpClient client = clientBuilder.build();

            WebSocket.Builder wsBuilder = client.newWebSocketBuilder();

            // Add custom headers
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                // Skip headers that Java's WS client doesn't allow
                String key = entry.getKey().toLowerCase();
                if (!key.equals("host") && !key.equals("upgrade") && !key.equals("connection")
                    && !key.equals("sec-websocket-key") && !key.equals("sec-websocket-version")) {
                    wsBuilder.header(entry.getKey(), entry.getValue());
                }
            }

            // Add subprotocol if specified
            if (subprotocol != null && !subprotocol.isEmpty()) {
                wsBuilder.subprotocols(subprotocol);
            }

            wsBuilder.buildAsync(URI.create(url), new WebSocket.Listener() {
                private StringBuilder messageBuffer = new StringBuilder();

                @Override
                public void onOpen(WebSocket webSocket) {
                    synchronized (connectionLock) {
                        connecting = false;
                        connected = true;
                        ws = webSocket;
                    }
                    status("Connected to " + url);
                    webSocket.request(1);

                    // Replay state chain
                    if (!stateChain.isEmpty()) {
                        status("Replaying state chain (" + stateChain.size() + " frames)...");
                        for (String frame : stateChain) {
                            try {
                                webSocket.sendText(frame, true);
                                Thread.sleep(200);  // Delay between state frames
                            } catch (Exception e) {
                                status("State chain replay failed: " + e.getMessage());
                            }
                        }
                        status("State chain replayed.");
                    }

                    result.complete(true);
                }

                @Override
                public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                    messageBuffer.append(data);
                    if (last) {
                        String msg = messageBuffer.toString();
                        messageBuffer = new StringBuilder();
                        handleIncoming(msg);
                    }
                    webSocket.request(1);
                    return null;
                }

                @Override
                public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
                    if (onBinaryMessage != null) {
                        byte[] bytes = new byte[data.remaining()];
                        data.get(bytes);
                        onBinaryMessage.accept(bytes);
                    }
                    webSocket.request(1);
                    return null;
                }

                @Override
                public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                    connected = false;
                    status("Disconnected: " + statusCode + " " + reason);
                    stopKeepalive();
                    return null;
                }

                @Override
                public void onError(WebSocket webSocket, Throwable error) {
                    synchronized (connectionLock) {
                        connecting = false;
                        connected = false;
                    }
                    status("Error: " + error.getMessage());
                    stopKeepalive();
                    result.completeExceptionally(error);
                }
            });

        } catch (Exception e) {
            synchronized (connectionLock) {
                connecting = false;
            }
            status("Connection failed: " + e.getMessage());
            result.completeExceptionally(e);
        }

        return result;
    }

    private void handleIncoming(String msg) {
        // Protocol detection
        if (detectedProtocol.equals("raw")) {
            detectedProtocol = ProtocolCodec.detectProtocol(Arrays.asList(msg));
        }

        // Auto-respond to Socket.IO pings
        if (detectedProtocol.equals("socket.io")) {
            if (msg.equals("2")) {
                // Engine.IO ping — respond with pong
                send("3");
                return;
            }
            if (msg.startsWith("0{")) {
                // Engine.IO open — extract ping interval
                try {
                    java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("\"pingInterval\"\\s*:\\s*(\\d+)")
                        .matcher(msg);
                    if (m.find()) {
                        socketIOPingInterval = Integer.parseInt(m.group(1));
                    }
                } catch (NumberFormatException e) {
                    // Keep default ping interval if parsing fails
                    status("Warning: Could not parse pingInterval, using default");
                }
                startKeepalive();
            }
        }

        if (onMessage != null) {
            onMessage.accept(msg);
        }
    }

    /**
     * Send a text frame on the connection.
     */
    public boolean send(String message) {
        if (ws != null && connected) {
            try {
                ws.sendText(message, true);
                return true;
            } catch (Exception e) {
                status("Send failed: " + e.getMessage());
            }
        }
        return false;
    }

    /**
     * Send multiple payloads with delay, for fuzzing.
     * Returns list of send results.
     */
    public List<FuzzResult> fuzz(String template, String fieldName, List<String> payloads,
                                  int delayMs, Consumer<FuzzResult> onEachResult) {
        List<FuzzResult> results = new ArrayList<>();

        for (int i = 0; i < payloads.size(); i++) {
            if (!connected) {
                // Reconnect
                status("Connection lost at payload " + i + " — reconnecting...");
                try {
                    connect(url).get(10, TimeUnit.SECONDS);
                    Thread.sleep(500);  // Wait for state chain
                } catch (Exception e) {
                    status("Reconnection failed: " + e.getMessage());
                    FuzzResult r = new FuzzResult(i, payloads.get(i), false, "Reconnection failed");
                    results.add(r);
                    if (onEachResult != null) onEachResult.accept(r);
                    continue;
                }
            }

            String payload = payloads.get(i);
            String modified = ProtocolCodec.replaceFieldValue(template, fieldName, payload);
            boolean sent = send(modified);

            FuzzResult r = new FuzzResult(i, payload, sent, modified);
            results.add(r);
            if (onEachResult != null) onEachResult.accept(r);

            if (delayMs > 0) {
                try { Thread.sleep(delayMs); } catch (InterruptedException e) { break; }
            }
        }

        return results;
    }

    /**
     * Disconnect gracefully.
     */
    public void disconnect() {
        stopKeepalive();
        synchronized (connectionLock) {
            connecting = false;
            connected = false;
            if (ws != null) {
                try {
                    ws.sendClose(1000, "Normal closure");
                } catch (Exception e) {
                    // Connection may already be closed - this is expected
                }
                ws = null;
            }
        }
    }

    public boolean isConnected() {
        return connected;
    }

    public String getDetectedProtocol() {
        return detectedProtocol;
    }

    private void startKeepalive() {
        stopKeepalive();
        if (detectedProtocol.equals("socket.io")) {
            keepaliveExecutor = Executors.newSingleThreadScheduledExecutor();
            // Socket.IO uses server-initiated pings, but we send proactive pongs
            // just in case. Also some implementations expect client pings.
        }
    }

    private void stopKeepalive() {
        if (keepaliveExecutor != null) {
            keepaliveExecutor.shutdownNow();
            keepaliveExecutor = null;
        }
    }

    private void status(String msg) {
        if (onStatus != null) onStatus.accept(msg);
    }

    public static class FuzzResult {
        public final int index;
        public final String payload;
        public final boolean sent;
        public final String fullFrame;

        public FuzzResult(int index, String payload, boolean sent, String fullFrame) {
            this.index = index;
            this.payload = payload;
            this.sent = sent;
            this.fullFrame = fullFrame;
        }
    }
}
