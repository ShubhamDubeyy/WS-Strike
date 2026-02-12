package wsstrike;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class FrameEntry {
    private static int nextId = 0;

    public final int id;
    public final String direction;      // "↑" (client→server) or "↓" (server→client)
    public final String raw;            // Raw frame data
    public final String url;            // WebSocket URL
    public final String protocol;       // "socket.io", "signalr", "actioncable", "graphql-ws", "raw"
    public final boolean isControl;     // Protocol control frame (ping/pong/connect)
    public final String eventName;      // Parsed event/target name (if applicable)
    public final String timestamp;
    public final int length;

    public ProtocolCodec.DecodedFrame decoded;

    public FrameEntry(String direction, String raw, String url, String protocol,
                      boolean isControl, String eventName) {
        this.id = nextId++;
        this.direction = direction;
        this.raw = raw;
        this.url = url;
        this.protocol = protocol;
        this.isControl = isControl;
        this.eventName = eventName != null ? eventName : "";
        this.timestamp = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
        this.length = raw != null ? raw.length() : 0;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s %s %s (%d bytes)",
            timestamp, direction, protocol, eventName, length);
    }
}
