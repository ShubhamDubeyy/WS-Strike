package wsstrike;

import java.util.*;
import java.util.regex.*;

/**
 * Detects and decodes WebSocket sub-protocols.
 * Handles: Socket.IO, SignalR, Action Cable, GraphQL-WS, STOMP, SockJS, Raw.
 */
public class ProtocolCodec {

    // Maximum input length to prevent ReDoS attacks
    private static final int MAX_INPUT_LENGTH = 1_000_000;  // 1MB max

    // ==================== DETECTION ====================

    public static String detectProtocol(List<String> frames) {
        if (frames == null || frames.isEmpty()) return "raw";

        for (String frame : frames) {
            if (frame == null) continue;
            // Limit input length to prevent ReDoS
            if (frame.length() > MAX_INPUT_LENGTH) continue;

            // Socket.IO: Engine.IO open packet starts with 0{
            if (frame.startsWith("0{") && frame.contains("\"sid\"")) return "socket.io";

            // Socket.IO: event frames start with 4X (simplified - no regex)
            if (frame.length() >= 2 && frame.charAt(0) == '4' &&
                frame.charAt(1) >= '0' && frame.charAt(1) <= '6') return "socket.io";

            // SignalR: frames end with \x1e (Record Separator)
            if (frame.endsWith("\u001e")) return "signalr";

            // Action Cable: welcome message
            if (frame.contains("\"type\":\"welcome\"")) return "actioncable";
            if (frame.contains("\"type\": \"welcome\"")) return "actioncable";

            // GraphQL-WS: connection_init
            if (frame.contains("\"type\":\"connection_init\"")) return "graphql-ws";
            if (frame.contains("\"type\":\"start\"")) return "graphql-ws";
            if (frame.contains("\"type\":\"subscribe\"")) return "graphql-ws";

            // STOMP: Commands start with known headers
            if (frame.startsWith("CONNECT") || frame.startsWith("CONNECTED") ||
                frame.startsWith("SEND") || frame.startsWith("SUBSCRIBE") ||
                frame.startsWith("MESSAGE") || frame.startsWith("STOMP")) {
                return "stomp";
            }

            // SockJS: Info or open frames
            if (frame.startsWith("o") && frame.length() == 1) return "sockjs";
            if (frame.startsWith("a[")) return "sockjs";
            if (frame.startsWith("h") && frame.length() == 1) return "sockjs";
        }

        // Check if first frame is pure JSON
        String first = frames.get(0).trim();
        if (first.startsWith("{") || first.startsWith("[")) {
            return "json";
        }

        return "raw";
    }

    // ==================== DECODING ====================

    public static DecodedFrame decode(String raw, String protocol) {
        if (raw == null) return new DecodedFrame(raw, "raw");

        switch (protocol) {
            case "socket.io":
                return decodeSocketIO(raw);
            case "signalr":
                return decodeSignalR(raw);
            case "actioncable":
                return decodeActionCable(raw);
            case "graphql-ws":
                return decodeGraphQLWS(raw);
            case "stomp":
                return decodeSTOMP(raw);
            case "sockjs":
                return decodeSockJS(raw);
            default:
                return decodeGeneric(raw);
        }
    }

    private static DecodedFrame decodeSocketIO(String raw) {
        // Engine.IO control frames
        if (raw.equals("2")) return new DecodedFrame(raw, "socket.io", true, "ping");
        if (raw.equals("3")) return new DecodedFrame(raw, "socket.io", true, "pong");
        if (raw.startsWith("0{")) return new DecodedFrame(raw, "socket.io", true, "open");
        if (raw.equals("1")) return new DecodedFrame(raw, "socket.io", true, "close");
        if (raw.equals("40") || raw.startsWith("40{") || raw.startsWith("40/"))
            return new DecodedFrame(raw, "socket.io", true, "connect");

        // Socket.IO event: 42["event",{data}] or 42/namespace,["event",{data}]
        Pattern eventPattern = Pattern.compile(
            "^(\\d)(\\d)(/[^,]*)?,?(\\d+)?\\[\"([^\"]+)\"(?:,(.*))?\\]$", Pattern.DOTALL
        );
        Matcher m = eventPattern.matcher(raw);
        if (m.matches()) {
            DecodedFrame frame = new DecodedFrame(raw, "socket.io");
            frame.engineIOType = m.group(1);
            frame.socketIOType = m.group(2);
            frame.namespace = m.group(3) != null ? m.group(3) : "/";
            frame.ackId = m.group(4);
            frame.eventName = m.group(5);
            frame.jsonData = m.group(6);

            // Parse JSON data if present
            if (frame.jsonData != null) {
                frame.parsedData = parseJsonFieldsDeep(frame.jsonData);
            }

            return frame;
        }

        // Socket.IO ack: 43["data"] or 431["data"]
        if (raw.matches("^4[3].*")) {
            DecodedFrame frame = new DecodedFrame(raw, "socket.io", false, "ack");
            return frame;
        }

        return new DecodedFrame(raw, "socket.io");
    }

    private static DecodedFrame decodeSignalR(String raw) {
        String clean = raw.endsWith("\u001e") ? raw.substring(0, raw.length() - 1) : raw;

        try {
            // Simple JSON parsing for type detection
            if (clean.contains("\"type\":6") || clean.contains("\"type\": 6")) {
                return new DecodedFrame(raw, "signalr", true, "ping");
            }
            if (clean.contains("\"type\":7") || clean.contains("\"type\": 7")) {
                return new DecodedFrame(raw, "signalr", true, "close");
            }

            DecodedFrame frame = new DecodedFrame(raw, "signalr");

            // Extract target for invocations (type 1)
            Pattern targetPattern = Pattern.compile("\"target\"\\s*:\\s*\"([^\"]+)\"");
            Matcher tm = targetPattern.matcher(clean);
            if (tm.find()) {
                frame.eventName = tm.group(1);
            }

            // Extract type
            Pattern typePattern = Pattern.compile("\"type\"\\s*:\\s*(\\d+)");
            Matcher typeM = typePattern.matcher(clean);
            if (typeM.find()) {
                int type = Integer.parseInt(typeM.group(1));
                frame.signalRType = type;
                switch (type) {
                    case 1: frame.signalRTypeName = "Invocation"; break;
                    case 2: frame.signalRTypeName = "StreamItem"; break;
                    case 3: frame.signalRTypeName = "Completion"; break;
                    case 4: frame.signalRTypeName = "StreamInvocation"; break;
                    case 5: frame.signalRTypeName = "CancelInvocation"; break;
                }
            }

            frame.jsonData = clean;
            frame.parsedData = parseJsonFieldsDeep(clean);
            return frame;

        } catch (Exception e) {
            return new DecodedFrame(raw, "signalr");
        }
    }

    private static DecodedFrame decodeActionCable(String raw) {
        DecodedFrame frame = new DecodedFrame(raw, "actioncable");

        // Detect control frames
        if (raw.contains("\"type\":\"welcome\"") || raw.contains("\"type\": \"welcome\"")) {
            frame.isControl = true;
            frame.eventName = "welcome";
            return frame;
        }
        if (raw.contains("\"type\":\"ping\"") || raw.contains("\"type\": \"ping\"")) {
            frame.isControl = true;
            frame.eventName = "ping";
            return frame;
        }
        if (raw.contains("\"type\":\"confirm_subscription\"")) {
            frame.isControl = true;
            frame.eventName = "confirm_subscription";
            return frame;
        }

        // Extract command
        Pattern cmdPattern = Pattern.compile("\"command\"\\s*:\\s*\"([^\"]+)\"");
        Matcher cm = cmdPattern.matcher(raw);
        if (cm.find()) {
            frame.eventName = cm.group(1);
        }

        // Extract inner data (double-encoded JSON)
        Pattern dataPattern = Pattern.compile("\"data\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher dm = dataPattern.matcher(raw);
        if (dm.find()) {
            String innerJson = dm.group(1)
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            frame.innerData = innerJson;
            frame.parsedData = parseJsonFieldsDeep(innerJson);
        }

        // Extract identifier (also double-encoded)
        Pattern idPattern = Pattern.compile("\"identifier\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher im = idPattern.matcher(raw);
        if (im.find()) {
            String innerIdentifier = im.group(1)
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            frame.innerIdentifier = innerIdentifier;
        }

        frame.jsonData = raw;
        return frame;
    }

    private static DecodedFrame decodeGraphQLWS(String raw) {
        DecodedFrame frame = new DecodedFrame(raw, "graphql-ws");

        // Detect message type
        Pattern typePattern = Pattern.compile("\"type\"\\s*:\\s*\"([^\"]+)\"");
        Matcher tm = typePattern.matcher(raw);
        if (tm.find()) {
            String type = tm.group(1);
            frame.eventName = type;

            // Control frames
            if (type.equals("connection_init") || type.equals("connection_ack") ||
                type.equals("ka") || type.equals("connection_keep_alive") ||
                type.equals("ping") || type.equals("pong")) {
                frame.isControl = true;
            }
        }

        // Extract subscription ID
        Pattern idPattern = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
        Matcher im = idPattern.matcher(raw);
        if (im.find()) {
            frame.subscriptionId = im.group(1);
        }

        // Extract variables from payload
        Pattern varsPattern = Pattern.compile("\"variables\"\\s*:\\s*(\\{[^}]*\\})");
        Matcher vm = varsPattern.matcher(raw);
        if (vm.find()) {
            frame.parsedData = parseJsonFieldsDeep(vm.group(1));
        }

        frame.jsonData = raw;
        return frame;
    }

    private static DecodedFrame decodeSTOMP(String raw) {
        DecodedFrame frame = new DecodedFrame(raw, "stomp");

        String[] lines = raw.split("\n");
        if (lines.length > 0) {
            String command = lines[0].trim();
            frame.eventName = command;

            // Control frames
            if (command.equals("CONNECTED") || command.equals("HEARTBEAT") ||
                command.equals("RECEIPT") || command.equals("ERROR")) {
                frame.isControl = true;
            }

            // Parse headers
            frame.parsedData = new LinkedHashMap<>();
            boolean inHeaders = true;
            StringBuilder body = new StringBuilder();

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (inHeaders && line.isEmpty()) {
                    inHeaders = false;
                    continue;
                }
                if (inHeaders) {
                    int colonIdx = line.indexOf(':');
                    if (colonIdx > 0) {
                        String key = line.substring(0, colonIdx);
                        String value = line.substring(colonIdx + 1);
                        frame.parsedData.put(key, value);
                    }
                } else {
                    body.append(line);
                }
            }

            if (body.length() > 0) {
                // Remove null terminator if present
                String bodyStr = body.toString().replace("\u0000", "");
                frame.jsonData = bodyStr;
                // Try to parse body as JSON
                if (bodyStr.trim().startsWith("{") || bodyStr.trim().startsWith("[")) {
                    Map<String, String> bodyFields = parseJsonFieldsDeep(bodyStr);
                    frame.parsedData.putAll(bodyFields);
                }
            }
        }

        return frame;
    }

    private static DecodedFrame decodeSockJS(String raw) {
        DecodedFrame frame = new DecodedFrame(raw, "sockjs");

        // SockJS frame types
        if (raw.equals("o")) {
            frame.isControl = true;
            frame.eventName = "open";
            return frame;
        }
        if (raw.equals("h")) {
            frame.isControl = true;
            frame.eventName = "heartbeat";
            return frame;
        }
        if (raw.startsWith("c[")) {
            frame.isControl = true;
            frame.eventName = "close";
            return frame;
        }

        // Message array: a["message1","message2"]
        if (raw.startsWith("a[")) {
            frame.eventName = "message";
            String inner = raw.substring(2, raw.length() - 1);
            // Unescape JSON strings
            frame.jsonData = inner;
            frame.parsedData = parseJsonFieldsDeep(inner);
        }

        return frame;
    }

    private static DecodedFrame decodeGeneric(String raw) {
        String trimmed = raw.trim().toUpperCase();

        // Detect common control/keepalive frames (case-insensitive)
        if (trimmed.equals("PING") || trimmed.equals("PONG") ||
            trimmed.equals("HEARTBEAT") || trimmed.equals("HB") ||
            trimmed.equals("KEEPALIVE") || trimmed.equals("KA") ||
            trimmed.equals("2") || trimmed.equals("3") ||  // Socket.IO style
            trimmed.equals("{}") || trimmed.equals("[]") ||  // Empty JSON
            trimmed.startsWith("{\"TYPE\":\"PING\"") || trimmed.startsWith("{\"TYPE\":\"PONG\"") ||
            trimmed.startsWith("{\"TYPE\": \"PING\"") || trimmed.startsWith("{\"TYPE\": \"PONG\"") ||
            trimmed.equals("PING\n") || trimmed.equals("PONG\n")) {

            String eventName = trimmed.equals("PING") || trimmed.contains("PING") ? "PING" :
                               trimmed.equals("PONG") || trimmed.contains("PONG") ? "PONG" :
                               trimmed.equals("2") ? "ping" :
                               trimmed.equals("3") ? "pong" : "keepalive";
            return new DecodedFrame(raw, "raw", true, eventName);
        }

        DecodedFrame frame = new DecodedFrame(raw, "raw");
        if (raw.trim().startsWith("{") || raw.trim().startsWith("[")) {
            frame.parsedData = parseJsonFieldsDeep(raw);
            frame.jsonData = raw;
        }
        return frame;
    }

    // ==================== ENCODING ====================

    /**
     * Re-encode a modified payload back into the protocol's envelope.
     */
    public static String encode(DecodedFrame original, String modifiedJsonData) {
        switch (original.protocol) {
            case "socket.io":
                return encodeSocketIO(original, modifiedJsonData);
            case "signalr":
                return encodeSignalR(original, modifiedJsonData);
            case "actioncable":
                return encodeActionCable(original, modifiedJsonData);
            case "stomp":
                return encodeSTOMP(original, modifiedJsonData);
            case "sockjs":
                return encodeSockJS(original, modifiedJsonData);
            default:
                return modifiedJsonData;
        }
    }

    private static String encodeSocketIO(DecodedFrame original, String modifiedData) {
        if (original.eventName == null) return original.raw;

        StringBuilder sb = new StringBuilder();
        sb.append(original.engineIOType != null ? original.engineIOType : "4");
        sb.append(original.socketIOType != null ? original.socketIOType : "2");

        if (original.namespace != null && !original.namespace.equals("/")) {
            sb.append(original.namespace).append(",");
        }
        if (original.ackId != null) {
            sb.append(original.ackId);
        }

        sb.append("[\"").append(original.eventName).append("\"");
        if (modifiedData != null && !modifiedData.isEmpty()) {
            sb.append(",").append(modifiedData);
        }
        sb.append("]");

        return sb.toString();
    }

    private static String encodeSignalR(DecodedFrame original, String modifiedData) {
        String result = modifiedData;
        if (!result.endsWith("\u001e")) {
            result += "\u001e";
        }
        return result;
    }

    private static String encodeActionCable(DecodedFrame original, String modifiedInnerData) {
        if (original.innerData == null) return original.raw;

        // Re-encode: stringify inner data, escape, wrap in outer
        String escaped = modifiedInnerData
            .replace("\\", "\\\\")
            .replace("\"", "\\\"");

        // Replace the data field in the original
        String result = original.raw.replaceFirst(
            "\"data\"\\s*:\\s*\"(?:[^\"\\\\]|\\\\.)*\"",
            "\"data\":\"" + escaped + "\""
        );

        return result;
    }

    private static String encodeSTOMP(DecodedFrame original, String modifiedBody) {
        // Reconstruct STOMP frame
        StringBuilder sb = new StringBuilder();
        sb.append(original.eventName).append("\n");

        if (original.parsedData != null) {
            for (Map.Entry<String, String> entry : original.parsedData.entrySet()) {
                // Skip body fields
                if (!entry.getKey().startsWith("_body_")) {
                    sb.append(entry.getKey()).append(":").append(entry.getValue()).append("\n");
                }
            }
        }

        sb.append("\n");
        sb.append(modifiedBody);
        sb.append("\u0000");

        return sb.toString();
    }

    private static String encodeSockJS(DecodedFrame original, String modifiedData) {
        if (original.eventName != null && original.eventName.equals("message")) {
            return "a[" + modifiedData + "]";
        }
        return modifiedData;
    }

    // ==================== FIELD REPLACEMENT ====================

    /**
     * Replace a value at a given JSON path in the raw data.
     * Supports nested paths like "user.profile.name" or "data.items[0].id"
     */
    public static String replaceFieldValue(String json, String fieldName, String newValue) {
        // Handle nested paths
        if (fieldName.contains(".")) {
            return replaceNestedField(json, fieldName, newValue);
        }

        // Handle array index
        if (fieldName.matches(".*\\[\\d+\\].*")) {
            return replaceArrayField(json, fieldName, newValue);
        }

        // Handle string values
        String pattern1 = "\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"[^\"]*\"";
        String replacement1 = "\"" + fieldName + "\":\"" + escapeJson(newValue) + "\"";
        String result = json.replaceFirst(pattern1, replacement1);

        if (!result.equals(json)) return result;

        // Handle numeric values
        String pattern2 = "\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*-?[\\d.]+";
        String replacement2 = "\"" + fieldName + "\":" + newValue;
        result = json.replaceFirst(pattern2, replacement2);

        if (!result.equals(json)) return result;

        // Handle boolean/null values
        String pattern3 = "\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*(true|false|null)";
        String replacement3 = "\"" + fieldName + "\":" + newValue;
        result = json.replaceFirst(pattern3, replacement3);

        return result;
    }

    private static String replaceNestedField(String json, String path, String newValue) {
        String[] parts = path.split("\\.");
        // For now, try direct regex replacement with nested structure
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < parts.length - 1; i++) {
            pattern.append("\"").append(Pattern.quote(parts[i])).append("\"\\s*:\\s*\\{[^}]*");
        }
        String lastField = parts[parts.length - 1];
        pattern.append("\"").append(Pattern.quote(lastField)).append("\"\\s*:\\s*\"[^\"]*\"");

        // This is a simplified approach - for complex nesting, a proper JSON parser would be needed
        return replaceFieldValue(json, lastField, newValue);
    }

    private static String replaceArrayField(String json, String path, String newValue) {
        // Extract field name and index
        Pattern p = Pattern.compile("(\\w+)\\[(\\d+)\\]");
        Matcher m = p.matcher(path);
        if (m.find()) {
            String fieldName = m.group(1);
            int index = Integer.parseInt(m.group(2));
            // Simplified - just replace the field value
            return replaceFieldValue(json, fieldName, newValue);
        }
        return json;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ==================== POSITION MARKER REPLACEMENT ====================

    /**
     * Find all position markers (§marker§) in the template
     */
    public static List<String> findPositionMarkers(String template) {
        List<String> markers = new ArrayList<>();
        Pattern p = Pattern.compile("§([^§]+)§");
        Matcher m = p.matcher(template);
        while (m.find()) {
            markers.add(m.group(1));
        }
        return markers;
    }

    /**
     * Replace a specific position marker with a value
     */
    public static String replacePositionMarker(String template, String marker, String value) {
        return template.replace("§" + marker + "§", value);
    }

    /**
     * Replace all position markers with values from a map
     */
    public static String replaceAllMarkers(String template, Map<String, String> values) {
        String result = template;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            result = result.replace("§" + entry.getKey() + "§", entry.getValue());
        }
        return result;
    }

    // ==================== JSON FIELD PARSING (IMPROVED) ====================

    /**
     * Extract key-value pairs from JSON string with support for nested objects.
     * Uses path notation for nested fields (e.g., "user.name", "data.items")
     */
    public static Map<String, String> parseJsonFieldsDeep(String json) {
        Map<String, String> fields = new LinkedHashMap<>();
        if (json == null) return fields;

        parseJsonRecursive(json.trim(), "", fields, 0);
        return fields;
    }

    private static void parseJsonRecursive(String json, String prefix, Map<String, String> fields, int depth) {
        if (depth > 10) return; // Prevent infinite recursion

        // Match "key": value patterns
        Pattern p = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|\\d+(?:\\.\\d+)?|true|false|null|\\{[^{}]*\\}|\\[[^\\[\\]]*\\])");
        Matcher m = p.matcher(json);

        while (m.find()) {
            String key = m.group(1);
            String value = m.group(2);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;

            // Remove surrounding quotes from string values
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
                // Unescape
                value = value.replace("\\\"", "\"").replace("\\\\", "\\");
                fields.put(fullKey, value);
            } else if (value.startsWith("{")) {
                // Nested object
                fields.put(fullKey, value);
                parseJsonRecursive(value, fullKey, fields, depth + 1);
            } else if (value.startsWith("[")) {
                // Array
                fields.put(fullKey, value);
                // Try to parse array elements
                parseArrayElements(value, fullKey, fields, depth);
            } else {
                // Number, boolean, null
                fields.put(fullKey, value);
            }
        }
    }

    private static void parseArrayElements(String arrayJson, String prefix, Map<String, String> fields, int depth) {
        if (depth > 10) return;

        // Simple array element extraction
        String inner = arrayJson.substring(1, arrayJson.length() - 1).trim();
        if (inner.isEmpty()) return;

        // Split by comma (simplified - doesn't handle nested commas well)
        int index = 0;
        int braceDepth = 0;
        int bracketDepth = 0;
        StringBuilder element = new StringBuilder();

        for (char c : inner.toCharArray()) {
            if (c == '{') braceDepth++;
            else if (c == '}') braceDepth--;
            else if (c == '[') bracketDepth++;
            else if (c == ']') bracketDepth--;
            else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                String elem = element.toString().trim();
                if (!elem.isEmpty()) {
                    fields.put(prefix + "[" + index + "]", elem);
                    if (elem.startsWith("{")) {
                        parseJsonRecursive(elem, prefix + "[" + index + "]", fields, depth + 1);
                    }
                }
                index++;
                element = new StringBuilder();
                continue;
            }
            element.append(c);
        }

        // Last element
        String lastElem = element.toString().trim();
        if (!lastElem.isEmpty()) {
            fields.put(prefix + "[" + index + "]", lastElem);
            if (lastElem.startsWith("{")) {
                parseJsonRecursive(lastElem, prefix + "[" + index + "]", fields, depth + 1);
            }
        }
    }

    /**
     * Legacy method for backwards compatibility
     */
    public static Map<String, String> parseJsonFields(String json) {
        return parseJsonFieldsDeep(json);
    }

    // ==================== DECODED FRAME MODEL ====================

    public static class DecodedFrame {
        public String raw;
        public String protocol;
        public boolean isControl;
        public String eventName;

        // Socket.IO specific
        public String engineIOType;
        public String socketIOType;
        public String namespace;
        public String ackId;

        // SignalR specific
        public int signalRType;
        public String signalRTypeName;

        // Action Cable specific
        public String innerData;
        public String innerIdentifier;

        // GraphQL specific
        public String subscriptionId;

        // Common
        public String jsonData;
        public Map<String, String> parsedData;

        public DecodedFrame(String raw, String protocol) {
            this.raw = raw;
            this.protocol = protocol;
            this.isControl = false;
        }

        public DecodedFrame(String raw, String protocol, boolean isControl, String eventName) {
            this.raw = raw;
            this.protocol = protocol;
            this.isControl = isControl;
            this.eventName = eventName;
        }

        /**
         * Get the fuzzable data portion of this frame.
         */
        public String getFuzzableData() {
            if (innerData != null) return innerData;      // Action Cable inner JSON
            if (jsonData != null) return jsonData;        // SignalR / GraphQL JSON
            if (parsedData != null && !parsedData.isEmpty()) {
                // Reconstruct from parsed fields
                StringBuilder sb = new StringBuilder("{");
                int i = 0;
                for (Map.Entry<String, String> entry : parsedData.entrySet()) {
                    if (i > 0) sb.append(",");
                    sb.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
                    i++;
                }
                sb.append("}");
                return sb.toString();
            }
            return raw;
        }
    }
}
