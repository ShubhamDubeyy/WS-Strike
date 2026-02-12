package wsstrike;

/*
 * WS-Strike — WebSocket Penetration Testing Toolkit
 * A professional Burp Suite extension for WebSocket security testing
 *
 * Author: Shubham (@ShubhamDubeyy)
 * Version: 1.0.0
 * License: MIT
 *
 * Features:
 * - Multi-protocol support (Socket.IO, SignalR, GraphQL-WS, Action Cable, STOMP, SockJS)
 * - Real-time traffic interception and modification
 * - Fuzzer with position markers and encoding options
 * - Repeater with state chain support
 * - CSWSH (Cross-Site WebSocket Hijacking) testing
 * - Quick tests for auth bypass and race conditions
 *
 * Repository: https://github.com/ShubhamDubeyy/ws-strike
 */

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class WSStrikeExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private WSStrikePanel panel;
    private final List<ActiveWebSocket> activeConnections = new CopyOnWriteArrayList<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        api.extension().setName("WS-Strike — WebSocket Pentest Toolkit");

        // Create the main UI panel
        panel = new WSStrikePanel(api, this);

        // Register the custom tab in Burp
        api.userInterface().registerSuiteTab("WS-Strike", panel);

        // Register WebSocket creation handler to track connections
        api.proxy().registerWebSocketCreationHandler(new ProxyWebSocketCreationHandler() {
            @Override
            public void handleWebSocketCreation(ProxyWebSocketCreation creation) {
                handleNewWebSocket(creation);
            }
        });

        logging.logToOutput("WS-Strike loaded successfully.");
        logging.logToOutput("═══════════════════════════════════════════════════════════");
        logging.logToOutput("  ⚡ WS-Strike v1.0.0 — WebSocket Penetration Testing Toolkit");
        logging.logToOutput("  Author: Shubham (@ShubhamDubeyy)");
        logging.logToOutput("  https://github.com/ShubhamDubeyy/ws-strike");
        logging.logToOutput("═══════════════════════════════════════════════════════════");
        logging.logToOutput("  Tabs: History | Intercept | Repeater | Fuzzer | Hijack Test | Quick Tests");
        logging.logToOutput("  Protocols: Socket.IO | SignalR | GraphQL-WS | Action Cable | STOMP | SockJS");
        logging.logToOutput("═══════════════════════════════════════════════════════════");
    }

    private void handleNewWebSocket(ProxyWebSocketCreation creation) {
        String url = extractWSUrl(creation);

        ActiveWebSocket activeWs = new ActiveWebSocket(url);
        activeConnections.add(activeWs);

        panel.onConnectionOpened(url);
        logging.logToOutput("[WS-Strike] New WebSocket connection: " + url);

        // Register message handler for this WebSocket
        creation.proxyWebSocket().registerProxyMessageHandler(new ProxyMessageHandler() {

            private final List<String> detectionFrames = new ArrayList<>();
            private String detectedProtocol = "raw";

            @Override
            public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
                String payload = message.payload();
                Direction dir = message.direction();
                boolean isFromClient = (dir == Direction.CLIENT_TO_SERVER);

                // Protocol detection on first frames
                if (detectionFrames.size() < 5) {
                    detectionFrames.add(payload);
                    detectedProtocol = ProtocolCodec.detectProtocol(detectionFrames);
                    activeWs.protocol = detectedProtocol;
                    panel.onProtocolDetected(url, detectedProtocol);
                }

                // Auto-respond to Socket.IO pings (Engine.IO ping = "2", pong = "3")
                if (detectedProtocol.equals("socket.io") && payload.equals("2") && !isFromClient) {
                    // Server sent ping — we need the CLIENT to respond with pong
                    // Log it but let it through — the browser will handle it
                    FrameEntry entry = new FrameEntry(
                        isFromClient ? "↑" : "↓", payload, url, detectedProtocol, true, "ping"
                    );
                    panel.addFrame(entry);
                    return TextMessageReceivedAction.continueWith(message);
                }

                // Decode the frame
                ProtocolCodec.DecodedFrame decoded = ProtocolCodec.decode(payload, detectedProtocol);

                // Create history entry
                FrameEntry entry = new FrameEntry(
                    isFromClient ? "↑" : "↓",
                    payload,
                    url,
                    detectedProtocol,
                    decoded.isControl,
                    decoded.eventName
                );
                entry.decoded = decoded;

                // Add to history
                panel.addFrame(entry);

                // Check if intercept is enabled
                if (panel.isInterceptEnabled() && !decoded.isControl) {
                    // Let the panel decide whether to forward, modify, or drop
                    String modified = panel.interceptFrame(entry);
                    if (modified == null) {
                        // Drop
                        return TextMessageReceivedAction.drop();
                    } else if (!modified.equals(payload)) {
                        // Modified
                        return TextMessageReceivedAction.continueWith(modified);
                    }
                }

                return TextMessageReceivedAction.continueWith(message);
            }

            @Override
            public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
                String payload = message.payload();

                // Log outgoing frames too
                ProtocolCodec.DecodedFrame decoded = ProtocolCodec.decode(payload, detectedProtocol);
                FrameEntry entry = new FrameEntry(
                    "↑", payload, url, detectedProtocol, decoded.isControl, decoded.eventName
                );
                entry.decoded = decoded;
                panel.addFrame(entry);

                if (panel.isInterceptEnabled() && !decoded.isControl) {
                    String modified = panel.interceptFrame(entry);
                    if (modified == null) {
                        return TextMessageToBeSentAction.drop();
                    } else if (!modified.equals(payload)) {
                        return TextMessageToBeSentAction.continueWith(modified);
                    }
                }

                return TextMessageToBeSentAction.continueWith(message);
            }

            @Override
            public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
                FrameEntry entry = new FrameEntry(
                    "↓", "[binary: " + message.payload().length() + " bytes]",
                    url, detectedProtocol, false, "binary"
                );
                panel.addFrame(entry);
                return BinaryMessageReceivedAction.continueWith(message);
            }

            @Override
            public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
                FrameEntry entry = new FrameEntry(
                    "↑", "[binary: " + message.payload().length() + " bytes]",
                    url, detectedProtocol, false, "binary"
                );
                panel.addFrame(entry);
                return BinaryMessageToBeSentAction.continueWith(message);
            }
        });
    }

    private String extractWSUrl(ProxyWebSocketCreation creation) {
        try {
            var request = creation.upgradeRequest();
            String host = request.headerValue("Host");
            String path = request.path();
            boolean isSecure = request.url().startsWith("https");
            return (isSecure ? "wss://" : "ws://") + host + path;
        } catch (Exception e) {
            return "unknown";
        }
    }

    public List<ActiveWebSocket> getActiveConnections() {
        return activeConnections;
    }

    // Represents a tracked WebSocket connection
    public static class ActiveWebSocket {
        public final String url;
        public String protocol = "raw";
        public boolean alive = true;

        public ActiveWebSocket(String url) {
            this.url = url;
        }
    }
}
