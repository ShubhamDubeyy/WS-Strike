package wsstrike;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class WSStrikePanel extends JPanel {

    private final MontoyaApi api;
    private final WSStrikeExtension extension;

    // Shared state
    private static final int MAX_FRAMES = 10000;  // Prevent memory exhaustion
    private final List<FrameEntry> allFrames = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean interceptEnabled = false;
    private final BlockingQueue<InterceptAction> interceptQueue = new LinkedBlockingQueue<>();

    // UI Components
    private JTabbedPane tabbedPane;
    private HistoryPanel historyPanel;
    private InterceptPanel interceptPanel;
    private RepeaterPanel repeaterPanel;
    private FuzzerPanel fuzzerPanel;
    private CSWSHPanel cswshPanel;
    private QuickTestPanel quickTestPanel;

    // Status bar
    private JLabel statusLabel;
    private JLabel protocolLabel;
    private JLabel frameCountLabel;

    // Colors
    private static final Color BG_DARK = new Color(30, 30, 30);
    private static final Color BG_PANEL = new Color(43, 43, 43);
    private static final Color BG_INPUT = new Color(50, 50, 50);
    private static final Color FG_PRIMARY = new Color(204, 204, 204);
    private static final Color FG_DIM = new Color(128, 128, 128);
    private static final Color ACCENT_GREEN = new Color(0, 200, 83);
    private static final Color ACCENT_BLUE = new Color(66, 165, 245);
    private static final Color ACCENT_ORANGE = new Color(255, 167, 38);
    private static final Color ACCENT_RED = new Color(244, 67, 54);
    private static final Color ACCENT_PURPLE = new Color(186, 104, 200);

    public WSStrikePanel(MontoyaApi api, WSStrikeExtension extension) {
        this.api = api;
        this.extension = extension;
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // Top status bar
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        statusBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(60, 60, 60)));

        JLabel titleLabel = new JLabel("⚡ WS-STRIKE v1.0");
        titleLabel.setFont(new Font("Monospaced", Font.BOLD, 14));
        titleLabel.setForeground(ACCENT_GREEN);
        titleLabel.setToolTipText("WS-Strike — WebSocket Pentest Toolkit by @ShubhamDubeyy");
        statusBar.add(titleLabel);

        statusBar.add(new JLabel(" | "));

        protocolLabel = new JLabel("Protocol: waiting...");
        protocolLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        statusBar.add(protocolLabel);

        statusBar.add(new JLabel(" | "));

        frameCountLabel = new JLabel("Frames: 0");
        frameCountLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        statusBar.add(frameCountLabel);

        statusBar.add(new JLabel(" | "));

        statusLabel = new JLabel("Waiting for WebSocket traffic through proxy...");
        statusLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        statusLabel.setForeground(FG_DIM);
        statusBar.add(statusLabel);

        add(statusBar, BorderLayout.NORTH);

        // Tabbed pane
        tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setFont(new Font("Monospaced", Font.BOLD, 11));

        historyPanel = new HistoryPanel();
        interceptPanel = new InterceptPanel();
        repeaterPanel = new RepeaterPanel();
        fuzzerPanel = new FuzzerPanel();
        cswshPanel = new CSWSHPanel();
        quickTestPanel = new QuickTestPanel();

        tabbedPane.addTab("History", historyPanel);
        tabbedPane.addTab("Intercept", interceptPanel);
        tabbedPane.addTab("Repeater", repeaterPanel);
        tabbedPane.addTab("Fuzzer", fuzzerPanel);
        tabbedPane.addTab("Hijack Test (CSWSH)", cswshPanel);
        tabbedPane.addTab("Quick Tests", quickTestPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    // ==================== PUBLIC API ====================

    public void addFrame(FrameEntry frame) {
        // Enforce memory limit - remove oldest frames if at capacity
        while (allFrames.size() >= MAX_FRAMES) {
            allFrames.remove(0);
        }
        allFrames.add(frame);
        SwingUtilities.invokeLater(() -> {
            historyPanel.addFrame(frame);
            frameCountLabel.setText("Frames: " + allFrames.size() + (allFrames.size() >= MAX_FRAMES - 100 ? " (near limit)" : ""));
        });
    }

    public void onConnectionOpened(String url) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Connected: " + url);
            statusLabel.setForeground(ACCENT_GREEN);
            repeaterPanel.setTargetUrl(url);
            fuzzerPanel.setTargetUrl(url);
            quickTestPanel.setTargetUrl(url);
        });
    }

    public void onProtocolDetected(String url, String protocol) {
        SwingUtilities.invokeLater(() -> {
            protocolLabel.setText("Protocol: " + protocol.toUpperCase());
            protocolLabel.setForeground(ACCENT_ORANGE);
        });
    }

    public boolean isInterceptEnabled() {
        return interceptEnabled;
    }

    /**
     * Called by the proxy handler when intercept is on.
     * Blocks until user decides to forward/drop/edit.
     * Returns modified payload, or null to drop.
     */
    public String interceptFrame(FrameEntry frame) {
        if (!interceptEnabled) return frame.raw;

        SwingUtilities.invokeLater(() -> interceptPanel.showFrame(frame));

        try {
            InterceptAction action = interceptQueue.poll(30, TimeUnit.SECONDS);
            if (action == null) return frame.raw;  // Timeout — forward unchanged
            return action.modifiedPayload;  // null = drop
        } catch (InterruptedException e) {
            return frame.raw;
        }
    }

    // ==================== HISTORY PANEL ====================

    private class HistoryPanel extends JPanel {
        private DefaultTableModel tableModel;
        private JTable table;
        private JTextArea detailArea;
        private JComboBox<String> filterCombo;
        private JTextField searchField;
        private JToggleButton userRequestsOnlyToggle;
        private boolean showUserRequestsOnly = false;  // Default: show all traffic
        private String searchQuery = "";

        HistoryPanel() {
            setLayout(new BorderLayout());

            // Toolbar
            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

            // User Requests Only toggle (most important filter)
            userRequestsOnlyToggle = new JToggleButton("📋 Show All Traffic", false);
            userRequestsOnlyToggle.setFont(new Font("Monospaced", Font.BOLD, 12));
            userRequestsOnlyToggle.setForeground(FG_DIM);
            userRequestsOnlyToggle.setToolTipText("Show only YOUR outgoing requests (hides ping/pong, server responses, control frames)");
            userRequestsOnlyToggle.addActionListener(e -> {
                showUserRequestsOnly = userRequestsOnlyToggle.isSelected();
                if (showUserRequestsOnly) {
                    userRequestsOnlyToggle.setText("👤 User Requests Only");
                    userRequestsOnlyToggle.setForeground(ACCENT_GREEN);
                    filterCombo.setEnabled(false);
                } else {
                    userRequestsOnlyToggle.setText("📋 Show All Traffic");
                    userRequestsOnlyToggle.setForeground(FG_DIM);
                    filterCombo.setEnabled(true);
                }
                applyFilter();
            });
            toolbar.add(userRequestsOnlyToggle);

            toolbar.add(new JLabel("  |  "));
            filterCombo = new JComboBox<>(new String[]{"All Directions", "Client → Server (↑)", "Server → Client (↓)"});
            filterCombo.setFont(new Font("Monospaced", Font.PLAIN, 11));
            filterCombo.setEnabled(true);  // Enabled by default (Show All Traffic mode)
            filterCombo.addActionListener(e -> applyFilter());
            toolbar.add(filterCombo);

            JButton clearBtn = new JButton("Clear");
            clearBtn.addActionListener(e -> {
                allFrames.clear();
                tableModel.setRowCount(0);
                detailArea.setText("");
            });
            toolbar.add(clearBtn);

            toolbar.add(new JLabel("  |  "));

            // Search field
            toolbar.add(new JLabel("Search: "));
            searchField = new JTextField(15);
            searchField.setFont(new Font("Monospaced", Font.PLAIN, 11));
            searchField.setToolTipText("Filter frames containing this text");
            searchField.addActionListener(e -> {
                searchQuery = searchField.getText().toLowerCase();
                applyFilter();
            });
            toolbar.add(searchField);

            JButton searchBtn = new JButton("🔍");
            searchBtn.addActionListener(e -> {
                searchQuery = searchField.getText().toLowerCase();
                applyFilter();
            });
            toolbar.add(searchBtn);

            toolbar.add(new JLabel("  |  "));

            // Export button
            JButton exportBtn = new JButton("📥 Export");
            exportBtn.setToolTipText("Export frames to JSON file");
            exportBtn.addActionListener(e -> exportFrames());
            toolbar.add(exportBtn);

            add(toolbar, BorderLayout.NORTH);

            // Table
            String[] columns = {"#", "Dir", "Time", "Len", "Protocol", "Event/Target", "Data"};
            tableModel = new DefaultTableModel(columns, 0) {
                @Override
                public boolean isCellEditable(int row, int col) { return false; }
            };
            table = new JTable(tableModel);
            table.setFont(new Font("Monospaced", Font.PLAIN, 12));
            table.setRowHeight(22);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

            // Column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
            table.getColumnModel().getColumn(1).setPreferredWidth(30);   // Dir
            table.getColumnModel().getColumn(2).setPreferredWidth(90);   // Time
            table.getColumnModel().getColumn(3).setPreferredWidth(50);   // Len
            table.getColumnModel().getColumn(4).setPreferredWidth(80);   // Protocol
            table.getColumnModel().getColumn(5).setPreferredWidth(120);  // Event
            table.getColumnModel().getColumn(6).setPreferredWidth(500);  // Data

            // Custom renderer that highlights user data frames and dims control frames
            DefaultTableCellRenderer frameRenderer = new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object val, boolean sel, boolean foc, int row, int col) {
                    Component c = super.getTableCellRendererComponent(t, val, sel, foc, row, col);

                    // Get frame ID from first column to check if it's a control frame
                    int frameId = (int) tableModel.getValueAt(row, 0);
                    FrameEntry frame = allFrames.stream().filter(f -> f.id == frameId).findFirst().orElse(null);
                    boolean isControl = frame != null && frame.isControl;

                    if (sel) {
                        c.setBackground(ACCENT_BLUE.darker());
                        c.setForeground(Color.WHITE);
                    } else if (isControl) {
                        // Dim control frames (ping/pong)
                        c.setBackground(BG_DARK);
                        c.setForeground(FG_DIM);
                    } else {
                        // Highlight user data frames
                        c.setBackground(BG_PANEL);
                        c.setForeground(FG_PRIMARY);
                    }
                    return c;
                }
            };

            // Apply renderer to all columns except direction
            for (int i = 0; i < table.getColumnCount(); i++) {
                if (i != 1) {
                    table.getColumnModel().getColumn(i).setCellRenderer(frameRenderer);
                }
            }

            // Direction column with colors
            table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object val, boolean sel, boolean foc, int row, int col) {
                    Component c = super.getTableCellRendererComponent(t, val, sel, foc, row, col);

                    int frameId = (int) tableModel.getValueAt(row, 0);
                    FrameEntry frame = allFrames.stream().filter(f -> f.id == frameId).findFirst().orElse(null);
                    boolean isControl = frame != null && frame.isControl;

                    String dir = val != null ? val.toString() : "";
                    if (sel) {
                        c.setBackground(ACCENT_BLUE.darker());
                    } else if (isControl) {
                        c.setBackground(BG_DARK);
                    } else {
                        c.setBackground(BG_PANEL);
                    }

                    if (dir.equals("↑")) c.setForeground(isControl ? FG_DIM : ACCENT_GREEN);
                    else if (dir.equals("↓")) c.setForeground(isControl ? FG_DIM : ACCENT_BLUE);
                    else c.setForeground(FG_DIM);
                    return c;
                }
            });

            // Right-click context menu
            JPopupMenu popup = new JPopupMenu();
            JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
            sendToRepeater.addActionListener(e -> {
                int row = table.getSelectedRow();
                if (row >= 0) sendFrameToRepeater(row);
            });
            JMenuItem sendToFuzzer = new JMenuItem("Send to Fuzzer");
            sendToFuzzer.addActionListener(e -> {
                int row = table.getSelectedRow();
                if (row >= 0) sendFrameToFuzzer(row);
            });
            JMenuItem copyRaw = new JMenuItem("Copy Raw Frame");
            copyRaw.addActionListener(e -> {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    FrameEntry frame = getFrameAtRow(row);
                    if (frame != null) {
                        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new java.awt.datatransfer.StringSelection(frame.raw), null);
                    }
                }
            });
            popup.add(sendToRepeater);
            popup.add(sendToFuzzer);
            popup.addSeparator();
            popup.add(copyRaw);
            table.setComponentPopupMenu(popup);

            // Selection listener
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int row = table.getSelectedRow();
                    if (row >= 0) showDetail(row);
                }
            });

            JScrollPane tableScroll = new JScrollPane(table);

            // Detail area
            detailArea = new JTextArea();
            detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            detailArea.setEditable(false);
            detailArea.setLineWrap(true);
            detailArea.setWrapStyleWord(true);
            JScrollPane detailScroll = new JScrollPane(detailArea);
            detailScroll.setPreferredSize(new Dimension(0, 200));

            // Split pane
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
            split.setDividerLocation(350);
            add(split, BorderLayout.CENTER);
        }

        void addFrame(FrameEntry f) {
            // User Requests Only mode: show only client→server data frames
            if (showUserRequestsOnly) {
                // Must be outgoing (↑) AND not a control frame
                if (!f.direction.equals("↑") || f.isControl) {
                    return;
                }
            } else {
                // Apply direction filter when not in User Requests Only mode
                String filter = (String) filterCombo.getSelectedItem();
                if ("Client → Server (↑)".equals(filter) && !f.direction.equals("↑")) return;
                if ("Server → Client (↓)".equals(filter) && !f.direction.equals("↓")) return;
            }

            String data = f.raw;
            if (f.decoded != null && f.decoded.jsonData != null) {
                data = f.decoded.jsonData;
            }
            if (data.length() > 200) data = data.substring(0, 200) + "...";

            tableModel.addRow(new Object[]{
                f.id, f.direction, f.timestamp, f.length,
                f.protocol, f.eventName, data
            });

            // Auto-scroll to bottom
            SwingUtilities.invokeLater(() -> {
                int lastRow = table.getRowCount() - 1;
                if (lastRow >= 0) table.scrollRectToVisible(table.getCellRect(lastRow, 0, true));
            });
        }

        void showDetail(int row) {
            FrameEntry frame = getFrameAtRow(row);
            if (frame == null) return;

            StringBuilder sb = new StringBuilder();
            sb.append("=== Frame #").append(frame.id).append(" ===\n");
            sb.append("Direction:  ").append(frame.direction.equals("↑") ? "Client → Server" : "Server → Client").append("\n");
            sb.append("Time:       ").append(frame.timestamp).append("\n");
            sb.append("URL:        ").append(frame.url).append("\n");
            sb.append("Protocol:   ").append(frame.protocol).append("\n");
            sb.append("Length:     ").append(frame.length).append(" bytes\n");

            if (frame.decoded != null) {
                sb.append("\n=== Protocol Decode ===\n");
                if (frame.decoded.eventName != null)
                    sb.append("Event:      ").append(frame.decoded.eventName).append("\n");
                if (frame.decoded.namespace != null)
                    sb.append("Namespace:  ").append(frame.decoded.namespace).append("\n");
                if (frame.decoded.ackId != null)
                    sb.append("Ack ID:     ").append(frame.decoded.ackId).append("\n");
                if (frame.decoded.signalRTypeName != null)
                    sb.append("Type:       ").append(frame.decoded.signalRTypeName).append("\n");
                if (frame.decoded.subscriptionId != null)
                    sb.append("Sub ID:     ").append(frame.decoded.subscriptionId).append("\n");

                if (frame.decoded.parsedData != null && !frame.decoded.parsedData.isEmpty()) {
                    sb.append("\n=== Parsed Fields (fuzzable) ===\n");
                    for (Map.Entry<String, String> entry : frame.decoded.parsedData.entrySet()) {
                        sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                }
            }

            sb.append("\n=== Raw Frame ===\n");
            sb.append(frame.raw);

            detailArea.setText(sb.toString());
            detailArea.setCaretPosition(0);
        }

        FrameEntry getFrameAtRow(int row) {
            if (row < 0 || row >= tableModel.getRowCount()) return null;
            int id = (int) tableModel.getValueAt(row, 0);
            return allFrames.stream().filter(f -> f.id == id).findFirst().orElse(null);
        }

        void applyFilter() {
            tableModel.setRowCount(0);
            int shown = 0;

            for (FrameEntry f : allFrames) {
                boolean show = true;

                if (showUserRequestsOnly) {
                    // User Requests Only: outgoing data frames only
                    show = f.direction.equals("↑") && !f.isControl;
                } else {
                    // Apply direction filter
                    String filter = (String) filterCombo.getSelectedItem();
                    if ("Client → Server (↑)".equals(filter)) show = f.direction.equals("↑");
                    else if ("Server → Client (↓)".equals(filter)) show = f.direction.equals("↓");
                }

                // Apply search filter
                if (show && !searchQuery.isEmpty()) {
                    show = f.raw.toLowerCase().contains(searchQuery) ||
                           (f.eventName != null && f.eventName.toLowerCase().contains(searchQuery)) ||
                           f.url.toLowerCase().contains(searchQuery);
                }

                if (show) {
                    String data = f.raw;
                    if (f.decoded != null && f.decoded.jsonData != null) {
                        data = f.decoded.jsonData;
                    }
                    if (data.length() > 200) data = data.substring(0, 200) + "...";
                    tableModel.addRow(new Object[]{f.id, f.direction, f.timestamp, f.length, f.protocol, f.eventName, data});
                    shown++;
                }
            }

            // Update frame count to show filtered vs total
            frameCountLabel.setText("Showing: " + shown + "/" + allFrames.size());
        }

        void exportFrames() {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Export Frames");
            fc.setSelectedFile(new java.io.File("ws-frames-" + System.currentTimeMillis() + ".json"));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try (java.io.PrintWriter pw = new java.io.PrintWriter(fc.getSelectedFile())) {
                    pw.println("[");
                    for (int i = 0; i < allFrames.size(); i++) {
                        FrameEntry f = allFrames.get(i);
                        String escaped = f.raw.replace("\\", "\\\\").replace("\"", "\\\"")
                                              .replace("\n", "\\n").replace("\r", "\\r");
                        pw.println("  {");
                        pw.println("    \"id\": " + f.id + ",");
                        pw.println("    \"direction\": \"" + f.direction + "\",");
                        pw.println("    \"timestamp\": \"" + f.timestamp + "\",");
                        pw.println("    \"url\": \"" + f.url.replace("\"", "\\\"") + "\",");
                        pw.println("    \"protocol\": \"" + f.protocol + "\",");
                        pw.println("    \"event\": \"" + (f.eventName != null ? f.eventName : "") + "\",");
                        pw.println("    \"length\": " + f.length + ",");
                        pw.println("    \"raw\": \"" + escaped + "\"");
                        pw.println("  }" + (i < allFrames.size() - 1 ? "," : ""));
                    }
                    pw.println("]");
                    statusLabel.setText("Exported " + allFrames.size() + " frames to " + fc.getSelectedFile().getName());
                    statusLabel.setForeground(ACCENT_GREEN);
                } catch (Exception ex) {
                    statusLabel.setText("Export failed: " + ex.getMessage());
                    statusLabel.setForeground(ACCENT_RED);
                }
            }
        }

        void sendFrameToRepeater(int row) {
            FrameEntry frame = getFrameAtRow(row);
            if (frame != null) {
                repeaterPanel.loadFrame(frame);
                tabbedPane.setSelectedComponent(repeaterPanel);
            }
        }

        void sendFrameToFuzzer(int row) {
            FrameEntry frame = getFrameAtRow(row);
            if (frame != null) {
                fuzzerPanel.loadFrame(frame);
                tabbedPane.setSelectedComponent(fuzzerPanel);
            }
        }
    }

    // ==================== INTERCEPT PANEL ====================

    private class InterceptPanel extends JPanel {
        private JToggleButton interceptToggle;
        private JTextArea frameArea;
        private JLabel interceptStatus;
        private FrameEntry currentFrame;  // Store current frame for send to repeater

        InterceptPanel() {
            setLayout(new BorderLayout(8, 8));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // Top controls
            JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

            interceptToggle = new JToggleButton("Intercept OFF");
            interceptToggle.setFont(new Font("Monospaced", Font.BOLD, 12));
            interceptToggle.addActionListener(e -> {
                interceptEnabled = interceptToggle.isSelected();
                interceptToggle.setText(interceptEnabled ? "Intercept ON" : "Intercept OFF");
                interceptToggle.setForeground(interceptEnabled ? ACCENT_RED : FG_DIM);
            });
            controls.add(interceptToggle);

            interceptStatus = new JLabel("Waiting for frames...");
            interceptStatus.setFont(new Font("Monospaced", Font.PLAIN, 11));
            interceptStatus.setForeground(FG_DIM);
            controls.add(interceptStatus);

            add(controls, BorderLayout.NORTH);

            // Frame editor
            frameArea = new JTextArea();
            frameArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
            frameArea.setLineWrap(true);
            frameArea.setWrapStyleWord(true);
            add(new JScrollPane(frameArea), BorderLayout.CENTER);

            // Action buttons
            JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

            JButton forwardBtn = new JButton("Forward");
            forwardBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            forwardBtn.addActionListener(e -> {
                interceptQueue.offer(new InterceptAction(frameArea.getText()));
                frameArea.setText("");
                interceptStatus.setText("Forwarded. Waiting...");
            });
            actions.add(forwardBtn);

            JButton dropBtn = new JButton("Drop");
            dropBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            dropBtn.setForeground(ACCENT_RED);
            dropBtn.addActionListener(e -> {
                interceptQueue.offer(new InterceptAction(null));
                frameArea.setText("");
                interceptStatus.setText("Dropped. Waiting...");
            });
            actions.add(dropBtn);

            JButton forwardOrigBtn = new JButton("Forward Original");
            forwardOrigBtn.addActionListener(e -> {
                // Forward without modifications
                if (currentFrame != null) {
                    interceptQueue.offer(new InterceptAction(currentFrame.raw));
                }
                frameArea.setText("");
            });
            actions.add(forwardOrigBtn);

            actions.add(new JLabel("  |  "));

            JButton sendToRepeaterBtn = new JButton("📤 Send to Repeater");
            sendToRepeaterBtn.setFont(new Font("Monospaced", Font.BOLD, 11));
            sendToRepeaterBtn.setForeground(ACCENT_BLUE);
            sendToRepeaterBtn.addActionListener(e -> {
                if (currentFrame != null) {
                    // Create a new frame with the edited content
                    FrameEntry editedFrame = new FrameEntry(
                        currentFrame.direction,
                        frameArea.getText(),
                        currentFrame.url,
                        currentFrame.protocol,
                        currentFrame.isControl,
                        currentFrame.eventName
                    );
                    editedFrame.decoded = currentFrame.decoded;
                    repeaterPanel.loadFrame(editedFrame);
                    tabbedPane.setSelectedComponent(repeaterPanel);
                    interceptStatus.setText("Sent to Repeater. Waiting...");
                    interceptStatus.setForeground(ACCENT_GREEN);
                }
            });
            actions.add(sendToRepeaterBtn);

            JButton sendToFuzzerBtn = new JButton("📤 Send to Fuzzer");
            sendToFuzzerBtn.setFont(new Font("Monospaced", Font.BOLD, 11));
            sendToFuzzerBtn.addActionListener(e -> {
                if (currentFrame != null) {
                    FrameEntry editedFrame = new FrameEntry(
                        currentFrame.direction,
                        frameArea.getText(),
                        currentFrame.url,
                        currentFrame.protocol,
                        currentFrame.isControl,
                        currentFrame.eventName
                    );
                    editedFrame.decoded = currentFrame.decoded;
                    fuzzerPanel.loadFrame(editedFrame);
                    tabbedPane.setSelectedComponent(fuzzerPanel);
                    interceptStatus.setText("Sent to Fuzzer. Waiting...");
                    interceptStatus.setForeground(ACCENT_GREEN);
                }
            });
            actions.add(sendToFuzzerBtn);

            add(actions, BorderLayout.SOUTH);
        }

        void showFrame(FrameEntry frame) {
            this.currentFrame = frame;
            frameArea.setText(frame.raw);
            interceptStatus.setText(frame.direction + " " + frame.protocol +
                (frame.eventName != null ? " [" + frame.eventName + "]" : "") +
                " — Edit and Forward or Drop");
            interceptStatus.setForeground(ACCENT_ORANGE);
        }
    }

    // ==================== REPEATER PANEL ====================

    private class RepeaterPanel extends JPanel {
        private JTextField urlField;
        private JTextField subprotocolField;  // WebSocket subprotocol (Sec-WebSocket-Protocol)
        private JTextArea requestArea;
        private JTextArea responseArea;
        private JTextArea headersArea;
        private JTextArea stateChainArea;
        private JLabel statusLabel;
        private WSConnection connection;
        private String targetUrl = "";
        private JButton connectBtn;
        private JButton disconnectBtn;
        private JButton reconnectBtn;
        // For comparison
        private String originalRequest = "";
        private String originalResponse = "";
        private List<String> allResponses = new ArrayList<>();

        RepeaterPanel() {
            setLayout(new BorderLayout(8, 8));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // Top — URL and connection controls
            JPanel topPanel = new JPanel(new BorderLayout(8, 4));
            JPanel urlPanel = new JPanel(new BorderLayout(8, 0));
            urlPanel.add(new JLabel("Target URL: "), BorderLayout.WEST);
            urlField = new JTextField();
            urlField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            urlPanel.add(urlField, BorderLayout.CENTER);

            // Connection buttons panel
            JPanel connBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));

            connectBtn = new JButton("🔌 Connect");
            connectBtn.setFont(new Font("Monospaced", Font.BOLD, 11));
            connectBtn.addActionListener(e -> connectRepeater());
            connBtnPanel.add(connectBtn);

            disconnectBtn = new JButton("❌ Disconnect");
            disconnectBtn.setFont(new Font("Monospaced", Font.BOLD, 11));
            disconnectBtn.setEnabled(false);
            disconnectBtn.addActionListener(e -> {
                if (connection != null) {
                    connection.disconnect();
                    connection = null;
                }
                updateConnectionButtons(false);
                statusLabel.setText("🔴 Disconnected by user");
                statusLabel.setForeground(ACCENT_RED);
            });
            connBtnPanel.add(disconnectBtn);

            reconnectBtn = new JButton("🔄 Reconnect");
            reconnectBtn.setFont(new Font("Monospaced", Font.BOLD, 11));
            reconnectBtn.setForeground(ACCENT_ORANGE);
            reconnectBtn.setVisible(false);
            reconnectBtn.addActionListener(e -> {
                reconnectBtn.setVisible(false);
                connectRepeater();
            });
            connBtnPanel.add(reconnectBtn);

            urlPanel.add(connBtnPanel, BorderLayout.EAST);
            topPanel.add(urlPanel, BorderLayout.NORTH);

            statusLabel = new JLabel("⚪ Enter WebSocket URL (wss://...) and click Connect");
            statusLabel.setFont(new Font("Monospaced", Font.BOLD, 11));
            statusLabel.setForeground(FG_DIM);
            statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
            topPanel.add(statusLabel, BorderLayout.SOUTH);

            add(topPanel, BorderLayout.NORTH);

            // Center — split between config and request/response
            JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

            // Left: config (headers + state chain)
            JPanel configPanel = new JPanel(new BorderLayout());
            JTabbedPane configTabs = new JTabbedPane();
            configTabs.setFont(new Font("Monospaced", Font.PLAIN, 10));

            // Headers tab with subprotocol field
            JPanel headersTab = new JPanel(new BorderLayout(4, 4));

            JPanel subprotoPanel = new JPanel(new BorderLayout(4, 0));
            subprotoPanel.add(new JLabel("Subprotocol: "), BorderLayout.WEST);
            subprotocolField = new JTextField();
            subprotocolField.setFont(new Font("Monospaced", Font.PLAIN, 11));
            subprotocolField.setToolTipText("Sec-WebSocket-Protocol header (e.g., graphql-ws, actioncable-v1-json)");
            subprotoPanel.add(subprotocolField, BorderLayout.CENTER);
            headersTab.add(subprotoPanel, BorderLayout.NORTH);

            headersArea = new JTextArea("Cookie: \nAuthorization: Bearer ");
            headersArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            headersTab.add(new JScrollPane(headersArea), BorderLayout.CENTER);
            configTabs.addTab("Headers", headersTab);

            stateChainArea = new JTextArea("# Paste frames to replay after connect (one per line)\n# These will be sent in order before your test frame\n");
            stateChainArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            configTabs.addTab("State Chain", new JScrollPane(stateChainArea));

            configPanel.add(configTabs, BorderLayout.CENTER);
            configPanel.setPreferredSize(new Dimension(300, 0));
            mainSplit.setLeftComponent(configPanel);

            // Right: request + response
            JSplitPane reqResSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            JPanel requestPanel = new JPanel(new BorderLayout());
            requestPanel.add(new JLabel(" Request (edit and send):"), BorderLayout.NORTH);
            requestArea = new JTextArea();
            requestArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
            requestArea.setLineWrap(true);
            requestPanel.add(new JScrollPane(requestArea), BorderLayout.CENTER);

            JPanel sendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton sendBtn = new JButton("📤 Send");
            sendBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            sendBtn.addActionListener(e -> sendRepeaterFrame());
            sendPanel.add(sendBtn);

            JButton pingBtn = new JButton("🔍 Check Connection");
            pingBtn.setToolTipText("Verify if WebSocket is still connected");
            pingBtn.addActionListener(e -> checkConnection());
            sendPanel.add(pingBtn);

            JButton saveOrigBtn = new JButton("💾 Save as Original");
            saveOrigBtn.setToolTipText("Save current request/response as baseline for comparison");
            saveOrigBtn.addActionListener(e -> {
                originalRequest = requestArea.getText();
                originalResponse = responseArea.getText();
                statusLabel.setText("🟢 Original saved for comparison");
                statusLabel.setForeground(ACCENT_GREEN);
            });
            sendPanel.add(saveOrigBtn);

            JButton compareBtn = new JButton("⚖ Compare");
            compareBtn.setToolTipText("Compare current response with saved original");
            compareBtn.addActionListener(e -> showComparison());
            sendPanel.add(compareBtn);

            JButton clearRespBtn = new JButton("🗑 Clear");
            clearRespBtn.addActionListener(e -> {
                responseArea.setText("");
                allResponses.clear();
            });
            sendPanel.add(clearRespBtn);

            requestPanel.add(sendPanel, BorderLayout.SOUTH);

            reqResSplit.setTopComponent(requestPanel);

            JPanel responsePanel = new JPanel(new BorderLayout());
            responsePanel.add(new JLabel(" Responses:"), BorderLayout.NORTH);
            responseArea = new JTextArea();
            responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            responseArea.setEditable(false);
            responseArea.setLineWrap(true);
            responsePanel.add(new JScrollPane(responseArea), BorderLayout.CENTER);
            reqResSplit.setBottomComponent(responsePanel);
            reqResSplit.setDividerLocation(300);

            mainSplit.setRightComponent(reqResSplit);
            mainSplit.setDividerLocation(300);

            add(mainSplit, BorderLayout.CENTER);
        }

        void setTargetUrl(String url) {
            this.targetUrl = url;
            urlField.setText(url);
        }

        void loadFrame(FrameEntry frame) {
            urlField.setText(frame.url);
            requestArea.setText(frame.raw);

            // Show decoded info
            if (frame.decoded != null && frame.decoded.parsedData != null) {
                StringBuilder sb = new StringBuilder();
                sb.append("# Decoded fields — edit values below then re-encode\n");
                for (Map.Entry<String, String> entry : frame.decoded.parsedData.entrySet()) {
                    sb.append("# ").append(entry.getKey()).append(" = ").append(entry.getValue()).append("\n");
                }
                sb.append("\n").append(frame.raw);
                requestArea.setText(sb.toString().trim());
            }

            // Auto-connect if not already connected
            if (connection == null || !connection.isConnected()) {
                statusLabel.setText("⚡ Auto-connecting...");
                statusLabel.setForeground(ACCENT_ORANGE);
                connectRepeater();
            }
        }

        void updateConnectionButtons(boolean connected) {
            SwingUtilities.invokeLater(() -> {
                connectBtn.setEnabled(!connected);
                disconnectBtn.setEnabled(connected);
                reconnectBtn.setVisible(!connected && urlField.getText().trim().length() > 0);
            });
        }

        void connectRepeater() {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                statusLabel.setText("🔴 Enter a WebSocket URL first (wss://... or ws://...)");
                statusLabel.setForeground(ACCENT_RED);
                return;
            }

            if (connection != null) connection.disconnect();
            connection = new WSConnection();

            // Set subprotocol if specified
            String subproto = subprotocolField.getText().trim();
            if (!subproto.isEmpty()) {
                connection.setSubprotocol(subproto);
            }

            // Parse headers
            Map<String, String> headers = new LinkedHashMap<>();
            for (String line : headersArea.getText().split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(":");
                if (idx > 0) {
                    headers.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
                }
            }
            connection.setHeaders(headers);

            // Parse state chain
            List<String> chain = new ArrayList<>();
            for (String line : stateChainArea.getText().split("\n")) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    chain.add(line);
                }
            }
            connection.setStateChain(chain);

            // Message handler
            connection.setOnMessage(msg -> SwingUtilities.invokeLater(() -> {
                // Skip ping/pong
                if (!msg.equals("2") && !msg.equals("3")) {
                    responseArea.append("[↓] " + msg + "\n\n");
                    responseArea.setCaretPosition(responseArea.getDocument().getLength());
                }
            }));

            connection.setOnStatus(s -> SwingUtilities.invokeLater(() -> {
                if (s.contains("Connected to")) {
                    statusLabel.setText("🟢 " + s);
                    statusLabel.setForeground(ACCENT_GREEN);
                    updateConnectionButtons(true);
                } else if (s.contains("Disconnected") || s.contains("Error") || s.contains("Failed")) {
                    statusLabel.setText("🔴 " + s + " — Click Reconnect to try again");
                    statusLabel.setForeground(ACCENT_RED);
                    updateConnectionButtons(false);
                } else if (s.contains("Connecting") || s.contains("Replaying")) {
                    statusLabel.setText("🟡 " + s);
                    statusLabel.setForeground(ACCENT_ORANGE);
                } else {
                    statusLabel.setText(s);
                    statusLabel.setForeground(FG_DIM);
                }
            }));

            statusLabel.setText("🟡 Connecting to " + url + "...");
            statusLabel.setForeground(ACCENT_ORANGE);
            connectBtn.setEnabled(false);

            new Thread(() -> {
                try {
                    boolean success = connection.connect(url).get(10, TimeUnit.SECONDS);
                    if (success) {
                        SwingUtilities.invokeLater(() -> updateConnectionButtons(true));
                    }
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("🔴 Connection failed: " + e.getMessage());
                        statusLabel.setForeground(ACCENT_RED);
                        updateConnectionButtons(false);
                    });
                }
            }).start();
        }

        void sendRepeaterFrame() {
            // Auto-connect if not connected
            if (connection == null || !connection.isConnected()) {
                statusLabel.setText("🟡 Auto-connecting before send...");
                statusLabel.setForeground(ACCENT_ORANGE);

                // Connect in background, then send
                new Thread(() -> {
                    connectRepeater();
                    // Wait for connection
                    int retries = 0;
                    while ((connection == null || !connection.isConnected()) && retries < 50) {
                        try { Thread.sleep(100); } catch (InterruptedException e) { break; }
                        retries++;
                    }
                    if (connection != null && connection.isConnected()) {
                        SwingUtilities.invokeLater(this::doSend);
                    }
                }).start();
                return;
            }
            doSend();
        }

        private void doSend() {
            // Strip comment lines
            StringBuilder raw = new StringBuilder();
            for (String line : requestArea.getText().split("\n")) {
                if (!line.startsWith("#")) raw.append(line);
            }

            String payload = raw.toString();
            if (payload.isEmpty()) {
                statusLabel.setText("🔴 Nothing to send — enter a message");
                statusLabel.setForeground(ACCENT_RED);
                return;
            }

            boolean sent = connection.send(payload);
            String timestamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            responseArea.append("[" + timestamp + " ↑ SENT] " + payload + "\n\n");
            responseArea.setCaretPosition(responseArea.getDocument().getLength());

            if (sent) {
                statusLabel.setText("🟢 Frame sent successfully");
                statusLabel.setForeground(ACCENT_GREEN);
            } else {
                statusLabel.setText("🔴 Send failed — connection may be lost");
                statusLabel.setForeground(ACCENT_RED);
                updateConnectionButtons(false);
            }
        }

        void checkConnection() {
            if (connection == null) {
                statusLabel.setText("🔴 No connection — click Connect first");
                statusLabel.setForeground(ACCENT_RED);
                updateConnectionButtons(false);
                return;
            }

            if (connection.isConnected()) {
                // Try to verify by checking internal state
                statusLabel.setText("🟢 Connection is ACTIVE");
                statusLabel.setForeground(ACCENT_GREEN);
                updateConnectionButtons(true);
            } else {
                statusLabel.setText("🔴 Connection is CLOSED — click Reconnect");
                statusLabel.setForeground(ACCENT_RED);
                updateConnectionButtons(false);
            }
        }

        void showComparison() {
            if (originalRequest.isEmpty() && originalResponse.isEmpty()) {
                statusLabel.setText("🟡 No original saved — click 'Save as Original' first");
                statusLabel.setForeground(ACCENT_ORANGE);
                return;
            }

            // Create comparison dialog
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Request/Response Comparison", true);
            dialog.setSize(900, 600);
            dialog.setLocationRelativeTo(this);

            JPanel mainPanel = new JPanel(new GridLayout(1, 2, 10, 10));
            mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // Original side
            JPanel origPanel = new JPanel(new BorderLayout());
            origPanel.setBorder(BorderFactory.createTitledBorder("Original"));
            JTextArea origArea = new JTextArea();
            origArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            origArea.setEditable(false);
            origArea.setText("=== REQUEST ===\n" + originalRequest + "\n\n=== RESPONSE ===\n" + originalResponse);
            origPanel.add(new JScrollPane(origArea), BorderLayout.CENTER);
            mainPanel.add(origPanel);

            // Current side
            JPanel currPanel = new JPanel(new BorderLayout());
            currPanel.setBorder(BorderFactory.createTitledBorder("Current"));
            JTextArea currArea = new JTextArea();
            currArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            currArea.setEditable(false);
            currArea.setText("=== REQUEST ===\n" + requestArea.getText() + "\n\n=== RESPONSE ===\n" + responseArea.getText());
            currPanel.add(new JScrollPane(currArea), BorderLayout.CENTER);
            mainPanel.add(currPanel);

            // Highlight differences
            boolean reqDiff = !originalRequest.equals(requestArea.getText());
            boolean respDiff = !originalResponse.equals(responseArea.getText());

            JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel diffLabel = new JLabel();
            if (reqDiff && respDiff) {
                diffLabel.setText("⚠ Both request and response DIFFER from original");
                diffLabel.setForeground(ACCENT_ORANGE);
            } else if (reqDiff) {
                diffLabel.setText("⚠ Request DIFFERS from original (response same)");
                diffLabel.setForeground(ACCENT_ORANGE);
            } else if (respDiff) {
                diffLabel.setText("⚠ Response DIFFERS from original (request same)");
                diffLabel.setForeground(ACCENT_ORANGE);
            } else {
                diffLabel.setText("✓ Request and response are IDENTICAL to original");
                diffLabel.setForeground(ACCENT_GREEN);
            }
            statusPanel.add(diffLabel);

            dialog.setLayout(new BorderLayout());
            dialog.add(mainPanel, BorderLayout.CENTER);
            dialog.add(statusPanel, BorderLayout.SOUTH);
            dialog.setVisible(true);
        }
    }

    // ==================== FUZZER PANEL ====================

    private class FuzzerPanel extends JPanel {
        private JTextField urlField;
        private JTextField subprotocolField;  // WebSocket subprotocol
        private JTextArea templateArea;
        private JPanel positionPanel;  // Panel with checkboxes for each marker
        private List<JCheckBox> positionCheckboxes = new ArrayList<>();
        private JComboBox<String> payloadCombo;
        private JTextArea customPayloadsArea;
        private JSpinner delaySpinner;
        private JTable resultsTable;
        private DefaultTableModel resultsModel;
        private JLabel fuzzStatus;
        private JTextArea headersArea;
        private JTextArea stateChainArea;
        private JTextArea responseLogArea;
        private volatile boolean fuzzRunning = false;
        private String targetUrl = "";
        private volatile int lastPayloadIndex = -1;
        private JComboBox<String> encodingCombo;

        FuzzerPanel() {
            setLayout(new BorderLayout(8, 8));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // Top config
            JPanel topPanel = new JPanel();
            topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));

            JPanel urlPanel = new JPanel(new BorderLayout(8, 0));
            urlPanel.add(new JLabel("URL: "), BorderLayout.WEST);
            urlField = new JTextField();
            urlField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            urlPanel.add(urlField, BorderLayout.CENTER);
            urlPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
            topPanel.add(urlPanel);
            topPanel.add(Box.createVerticalStrut(4));

            add(topPanel, BorderLayout.NORTH);

            // Main split
            JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

            // Left: template + config
            JPanel leftPanel = new JPanel(new BorderLayout(4, 4));

            JTabbedPane leftTabs = new JTabbedPane();
            leftTabs.setFont(new Font("Monospaced", Font.PLAIN, 10));

            // Template tab - now uses position markers (§value§)
            JPanel templatePanel = new JPanel(new BorderLayout(4, 4));
            JPanel templateHeader = new JPanel(new BorderLayout());
            templateHeader.add(new JLabel(" Frame template — mark fuzz positions with §value§:"), BorderLayout.WEST);
            JButton insertMarkerBtn = new JButton("§§");
            insertMarkerBtn.setToolTipText("Insert position marker at cursor");
            insertMarkerBtn.addActionListener(e -> {
                int pos = templateArea.getCaretPosition();
                try {
                    templateArea.getDocument().insertString(pos, "§payload§", null);
                } catch (Exception ex) {}
                updatePositionMarkers();
            });
            templateHeader.add(insertMarkerBtn, BorderLayout.EAST);
            templatePanel.add(templateHeader, BorderLayout.NORTH);

            templateArea = new JTextArea();
            templateArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
            templateArea.setLineWrap(true);
            // Auto-detect markers when template changes
            templateArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void insertUpdate(javax.swing.event.DocumentEvent e) { updatePositionMarkers(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { updatePositionMarkers(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { updatePositionMarkers(); }
            });
            templatePanel.add(new JScrollPane(templateArea), BorderLayout.CENTER);

            JPanel markerPanel = new JPanel(new BorderLayout(4, 0));
            markerPanel.add(new JLabel("Fuzz positions: "), BorderLayout.WEST);
            positionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            positionPanel.add(new JLabel("(add §marker§ to template)"));
            markerPanel.add(positionPanel, BorderLayout.CENTER);
            JButton selectAllBtn = new JButton("All");
            selectAllBtn.setFont(new Font("Monospaced", Font.PLAIN, 10));
            selectAllBtn.addActionListener(e -> {
                for (JCheckBox cb : positionCheckboxes) cb.setSelected(true);
            });
            markerPanel.add(selectAllBtn, BorderLayout.EAST);
            templatePanel.add(markerPanel, BorderLayout.SOUTH);

            leftTabs.addTab("Template", templatePanel);

            // Headers tab with subprotocol
            JPanel headersTab = new JPanel(new BorderLayout(4, 4));
            JPanel subprotoPanel = new JPanel(new BorderLayout(4, 0));
            subprotoPanel.add(new JLabel("Subprotocol: "), BorderLayout.WEST);
            subprotocolField = new JTextField();
            subprotocolField.setFont(new Font("Monospaced", Font.PLAIN, 11));
            subprotocolField.setToolTipText("Sec-WebSocket-Protocol (e.g., graphql-ws)");
            subprotoPanel.add(subprotocolField, BorderLayout.CENTER);
            headersTab.add(subprotoPanel, BorderLayout.NORTH);

            headersArea = new JTextArea("Cookie: \nAuthorization: Bearer ");
            headersArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            headersTab.add(new JScrollPane(headersArea), BorderLayout.CENTER);
            leftTabs.addTab("Headers", headersTab);

            // State chain tab
            stateChainArea = new JTextArea("# Frames to replay after reconnection\n");
            stateChainArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            leftTabs.addTab("State Chain", new JScrollPane(stateChainArea));

            leftPanel.add(leftTabs, BorderLayout.CENTER);

            // Payload config
            JPanel payloadConfig = new JPanel();
            payloadConfig.setLayout(new BoxLayout(payloadConfig, BoxLayout.Y_AXIS));
            payloadConfig.setBorder(BorderFactory.createTitledBorder("Payloads"));

            JPanel payloadTypePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            payloadTypePanel.add(new JLabel("Payload list:"));
            payloadCombo = new JComboBox<>(Payloads.ALL.keySet().toArray(new String[0]));
            payloadCombo.addItem("Custom");
            payloadCombo.setFont(new Font("Monospaced", Font.PLAIN, 11));
            payloadTypePanel.add(payloadCombo);
            payloadTypePanel.add(new JLabel("  Delay (ms):"));
            delaySpinner = new JSpinner(new SpinnerNumberModel(100, 0, 10000, 50));
            payloadTypePanel.add(delaySpinner);

            payloadTypePanel.add(new JLabel("  Encode:"));
            encodingCombo = new JComboBox<>(new String[]{"None", "URL Encode", "Base64", "Double URL", "Unicode"});
            encodingCombo.setFont(new Font("Monospaced", Font.PLAIN, 11));
            encodingCombo.setToolTipText("Apply encoding to payloads before sending");
            payloadTypePanel.add(encodingCombo);

            payloadConfig.add(payloadTypePanel);

            // Custom payloads section with load button
            JPanel customPanel = new JPanel(new BorderLayout(4, 4));
            customPanel.setBorder(BorderFactory.createTitledBorder("Custom Payloads (one per line)"));

            customPayloadsArea = new JTextArea(6, 30);
            customPayloadsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            customPayloadsArea.setText("# Enter your payloads here (one per line)\n# Or click 'Load from File' to import a wordlist\n");
            customPanel.add(new JScrollPane(customPayloadsArea), BorderLayout.CENTER);

            JPanel customBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton loadFileBtn = new JButton("📂 Load from File");
            loadFileBtn.addActionListener(e -> {
                JFileChooser fc = new JFileChooser();
                fc.setDialogTitle("Select Payload Wordlist");
                if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                    try {
                        java.util.List<String> lines = java.nio.file.Files.readAllLines(fc.getSelectedFile().toPath());
                        customPayloadsArea.setText(String.join("\n", lines));
                        payloadCombo.setSelectedItem("Custom");
                        fuzzStatus.setText("✓ Loaded " + lines.size() + " payloads from file");
                        fuzzStatus.setForeground(ACCENT_GREEN);
                    } catch (Exception ex) {
                        fuzzStatus.setText("Failed to load file: " + ex.getMessage());
                        fuzzStatus.setForeground(ACCENT_RED);
                    }
                }
            });
            customBtnPanel.add(loadFileBtn);

            JButton clearBtn = new JButton("Clear");
            clearBtn.addActionListener(e -> customPayloadsArea.setText(""));
            customBtnPanel.add(clearBtn);

            JLabel countLabel = new JLabel("0 payloads");
            countLabel.setForeground(FG_DIM);
            customPayloadsArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                void update() {
                    long count = customPayloadsArea.getText().lines()
                        .filter(l -> !l.trim().isEmpty() && !l.trim().startsWith("#")).count();
                    countLabel.setText(count + " payloads");
                }
                public void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
            });
            customBtnPanel.add(countLabel);

            customPanel.add(customBtnPanel, BorderLayout.SOUTH);
            payloadConfig.add(customPanel);

            leftPanel.add(payloadConfig, BorderLayout.SOUTH);
            mainSplit.setLeftComponent(leftPanel);

            // Right: controls + results
            JPanel rightPanel = new JPanel(new BorderLayout(4, 4));

            JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton startBtn = new JButton("▶ Start Fuzzing");
            startBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            startBtn.addActionListener(e -> startFuzz());
            controlPanel.add(startBtn);

            JButton stopBtn = new JButton("■ Stop");
            stopBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            stopBtn.setForeground(ACCENT_RED);
            stopBtn.addActionListener(e -> fuzzRunning = false);
            controlPanel.add(stopBtn);

            JButton clearResultsBtn = new JButton("🗑 Clear Results");
            clearResultsBtn.addActionListener(e -> {
                resultsModel.setRowCount(0);
                responseLogArea.setText("");
                fuzzStatus.setText("Ready");
                fuzzStatus.setForeground(FG_DIM);
            });
            controlPanel.add(clearResultsBtn);

            fuzzStatus = new JLabel("Ready");
            fuzzStatus.setFont(new Font("Monospaced", Font.PLAIN, 11));
            controlPanel.add(fuzzStatus);

            rightPanel.add(controlPanel, BorderLayout.NORTH);

            // Results table with Response and Length columns
            String[] cols = {"#", "Payload", "Sent", "Len", "Response"};
            resultsModel = new DefaultTableModel(cols, 0) {
                @Override
                public boolean isCellEditable(int r, int c) { return false; }
            };
            resultsTable = new JTable(resultsModel);
            resultsTable.setFont(new Font("Monospaced", Font.PLAIN, 11));
            resultsTable.setRowHeight(24);
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(40);
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(180);
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(35);
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(50);
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(350);

            // Split: results table on top, response log on bottom
            JSplitPane resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            resultsSplit.setTopComponent(new JScrollPane(resultsTable));

            // Response log area
            JPanel responsePanel = new JPanel(new BorderLayout());
            responsePanel.add(new JLabel(" 📥 Server Responses:"), BorderLayout.NORTH);
            responseLogArea = new JTextArea();
            responseLogArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            responseLogArea.setEditable(false);
            responseLogArea.setLineWrap(true);
            responsePanel.add(new JScrollPane(responseLogArea), BorderLayout.CENTER);
            resultsSplit.setBottomComponent(responsePanel);
            resultsSplit.setDividerLocation(250);

            rightPanel.add(resultsSplit, BorderLayout.CENTER);
            mainSplit.setRightComponent(rightPanel);
            mainSplit.setDividerLocation(500);

            add(mainSplit, BorderLayout.CENTER);
        }

        void setTargetUrl(String url) {
            this.targetUrl = url;
            urlField.setText(url);
        }

        void loadFrame(FrameEntry frame) {
            urlField.setText(frame.url);

            // Auto-wrap the first string value with position markers for easy fuzzing
            String template = frame.raw;
            if (frame.decoded != null && frame.decoded.parsedData != null && !frame.decoded.parsedData.isEmpty()) {
                // Find first non-object value to wrap
                for (Map.Entry<String, String> entry : frame.decoded.parsedData.entrySet()) {
                    String val = entry.getValue();
                    if (!val.startsWith("{") && !val.startsWith("[")) {
                        // Wrap this value with position markers
                        template = template.replace("\"" + val + "\"", "\"§payload§\"");
                        break;
                    }
                }
            }
            templateArea.setText(template);
            updatePositionMarkers();

            fuzzStatus.setText("⚡ Frame loaded — mark positions with §value§ then fuzz");
            fuzzStatus.setForeground(ACCENT_GREEN);
        }

        void updatePositionMarkers() {
            List<String> markers = ProtocolCodec.findPositionMarkers(templateArea.getText());
            positionPanel.removeAll();
            positionCheckboxes.clear();

            if (markers.isEmpty()) {
                JLabel hint = new JLabel("(add §marker§ to template)");
                hint.setForeground(FG_DIM);
                positionPanel.add(hint);
            } else {
                for (String marker : markers) {
                    JCheckBox cb = new JCheckBox("§" + marker + "§", true);
                    cb.setFont(new Font("Monospaced", Font.BOLD, 11));
                    cb.setForeground(ACCENT_GREEN);
                    cb.putClientProperty("marker", marker);
                    positionCheckboxes.add(cb);
                    positionPanel.add(cb);
                }
            }
            positionPanel.revalidate();
            positionPanel.repaint();
        }

        List<String> getSelectedMarkers() {
            List<String> selected = new ArrayList<>();
            for (JCheckBox cb : positionCheckboxes) {
                if (cb.isSelected()) {
                    selected.add((String) cb.getClientProperty("marker"));
                }
            }
            return selected;
        }

        String encodePayload(String payload, String encoding) {
            if (payload == null || encoding == null || encoding.equals("None")) {
                return payload;
            }
            try {
                switch (encoding) {
                    case "URL Encode":
                        return java.net.URLEncoder.encode(payload, "UTF-8");
                    case "Base64":
                        return java.util.Base64.getEncoder().encodeToString(payload.getBytes("UTF-8"));
                    case "Double URL":
                        String first = java.net.URLEncoder.encode(payload, "UTF-8");
                        return java.net.URLEncoder.encode(first, "UTF-8");
                    case "Unicode":
                        StringBuilder sb = new StringBuilder();
                        for (char c : payload.toCharArray()) {
                            sb.append(String.format("\\u%04x", (int) c));
                        }
                        return sb.toString();
                    default:
                        return payload;
                }
            } catch (Exception e) {
                return payload;
            }
        }

        void startFuzz() {
            if (fuzzRunning) return;

            String template = templateArea.getText().trim();
            String url = urlField.getText().trim();

            if (template.isEmpty() || url.isEmpty()) {
                fuzzStatus.setText("Fill in URL and template");
                fuzzStatus.setForeground(ACCENT_RED);
                return;
            }

            // Check for selected position markers
            List<String> markers = getSelectedMarkers();
            if (markers.isEmpty()) {
                fuzzStatus.setText("No positions selected — check at least one §marker§");
                fuzzStatus.setForeground(ACCENT_RED);
                return;
            }

            // Get payloads
            List<String> payloads;
            String selectedPayload = (String) payloadCombo.getSelectedItem();
            if ("Custom".equals(selectedPayload)) {
                payloads = new ArrayList<>();
                for (String line : customPayloadsArea.getText().split("\n")) {
                    if (!line.trim().isEmpty()) payloads.add(line.trim());
                }
            } else {
                payloads = Payloads.ALL.get(selectedPayload);
            }

            if (payloads == null || payloads.isEmpty()) {
                fuzzStatus.setText("No payloads selected");
                return;
            }

            int delay = (int) delaySpinner.getValue();
            resultsModel.setRowCount(0);
            responseLogArea.setText("");  // Clear response log
            lastPayloadIndex = -1;
            fuzzRunning = true;
            fuzzStatus.setText("🟡 Connecting...");
            fuzzStatus.setForeground(ACCENT_ORANGE);

            final String fuzzTemplate = template;
            final List<String> fuzzMarkers = markers;

            // Run fuzz in background
            new Thread(() -> {
                WSConnection conn = new WSConnection();

                // Set subprotocol if specified
                String subproto = subprotocolField.getText().trim();
                if (!subproto.isEmpty()) {
                    conn.setSubprotocol(subproto);
                }

                // Parse headers
                Map<String, String> headers = new LinkedHashMap<>();
                for (String line : headersArea.getText().split("\n")) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    int idx = line.indexOf(":");
                    if (idx > 0) headers.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
                }
                conn.setHeaders(headers);

                // State chain
                List<String> chain = new ArrayList<>();
                for (String line : stateChainArea.getText().split("\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) chain.add(line);
                }
                conn.setStateChain(chain);

                conn.setOnMessage(msg -> SwingUtilities.invokeLater(() -> {
                    // Skip ping/pong control frames
                    if (msg.equals("2") || msg.equals("3")) return;

                    // Log response with timestamp
                    String timestamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
                    responseLogArea.append("[" + timestamp + "] " + msg + "\n");

                    // Update the Length and Response columns for the last sent payload
                    int rowCount = resultsModel.getRowCount();
                    if (rowCount > 0) {
                        int lastRow = rowCount - 1;
                        // Update length
                        Object existingLen = resultsModel.getValueAt(lastRow, 3);
                        int prevLen = 0;
                        if (existingLen != null && !existingLen.toString().equals("—")) {
                            try { prevLen = Integer.parseInt(existingLen.toString()); } catch (Exception e) {}
                        }
                        resultsModel.setValueAt(String.valueOf(prevLen + msg.length()), lastRow, 3);

                        // Update response preview
                        String existing = (String) resultsModel.getValueAt(lastRow, 4);
                        String shortened = msg.length() > 80 ? msg.substring(0, 80) + "..." : msg;
                        if (existing == null || existing.isEmpty() || existing.equals("—")) {
                            resultsModel.setValueAt(shortened, lastRow, 4);
                        } else {
                            resultsModel.setValueAt(existing + " | " + shortened, lastRow, 4);
                        }
                    }

                    // Auto-scroll response log
                    responseLogArea.setCaretPosition(responseLogArea.getDocument().getLength());
                }));
                conn.setOnStatus(s -> SwingUtilities.invokeLater(() -> {
                    if (s.contains("Connected")) {
                        fuzzStatus.setText("🟢 " + s);
                        fuzzStatus.setForeground(ACCENT_GREEN);
                    } else if (s.contains("Error") || s.contains("Failed") || s.contains("Disconnected")) {
                        fuzzStatus.setText("🔴 " + s);
                        fuzzStatus.setForeground(ACCENT_RED);
                    } else {
                        fuzzStatus.setText(s);
                    }
                }));

                try {
                    conn.connect(url).get(10, TimeUnit.SECONDS);

                    final List<String> finalPayloads = payloads;
                    responseLogArea.setText("");  // Clear previous responses

                    // Get encoding setting
                    final String encoding = (String) encodingCombo.getSelectedItem();

                    // Use position markers to inject payloads
                    for (int i = 0; i < finalPayloads.size() && fuzzRunning; i++) {
                        String payload = finalPayloads.get(i);
                        String encodedPayload = encodePayload(payload, encoding);

                        // Replace all position markers with the encoded payload
                        String modified = fuzzTemplate;
                        for (String marker : fuzzMarkers) {
                            modified = ProtocolCodec.replacePositionMarker(modified, marker, encodedPayload);
                        }

                        boolean sent = conn.send(modified);
                        final int idx = i;
                        final String pld = payload;
                        lastPayloadIndex = i;

                        SwingUtilities.invokeLater(() -> {
                            resultsModel.addRow(new Object[]{
                                idx + 1,
                                pld.length() > 50 ? pld.substring(0, 50) + "..." : pld,
                                sent ? "✓" : "✗",
                                "—",  // Length placeholder
                                "—"   // Response placeholder
                            });
                            fuzzStatus.setText("🟡 Fuzzing: " + (idx + 1) + "/" + finalPayloads.size());
                            fuzzStatus.setForeground(ACCENT_ORANGE);

                            // Auto-scroll
                            int last = resultsTable.getRowCount() - 1;
                            if (last >= 0) resultsTable.scrollRectToVisible(resultsTable.getCellRect(last, 0, true));
                        });

                        if (delay > 0) {
                            try { Thread.sleep(delay); } catch (InterruptedException e) { break; }
                        }

                        // Reconnect if disconnected
                        if (!conn.isConnected() && fuzzRunning) {
                            SwingUtilities.invokeLater(() -> {
                                fuzzStatus.setText("🟡 Reconnecting...");
                                fuzzStatus.setForeground(ACCENT_ORANGE);
                            });
                            try {
                                conn.connect(url).get(10, TimeUnit.SECONDS);
                                Thread.sleep(500);
                            } catch (Exception re) {
                                // Continue anyway
                            }
                        }
                    }
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        fuzzStatus.setText("Connection failed: " + e.getMessage());
                        fuzzStatus.setForeground(ACCENT_RED);
                    });
                } finally {
                    conn.disconnect();
                    fuzzRunning = false;
                    SwingUtilities.invokeLater(() -> {
                        fuzzStatus.setText("Done. " + resultsModel.getRowCount() + " payloads sent.");
                        fuzzStatus.setForeground(ACCENT_GREEN);
                    });
                }
            }).start();
        }
    }

    // ==================== CSWSH PANEL ====================

    private class CSWSHPanel extends JPanel {
        private JTextField targetField;
        private JTextArea resultArea;
        private JTextArea pocArea;
        private List<String> findings = new ArrayList<>();
        private List<String> notes = new ArrayList<>();  // Non-vulnerability notes

        CSWSHPanel() {
            setLayout(new BorderLayout(8, 8));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.add(new JLabel("<html><b>🔓 Cross-Site WebSocket Hijacking (CSWSH) Analysis</b><br>" +
                "Analyzes WebSocket URL for potential CSWSH vectors.<br>" +
                "<span style='color:orange'>⚠ NOTE: Actual CSWSH testing requires the HTML PoC in a browser!</span></html>"),
                BorderLayout.NORTH);

            JPanel urlPanel = new JPanel(new BorderLayout(8, 0));
            urlPanel.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0));
            urlPanel.add(new JLabel("Target WS URL: "), BorderLayout.WEST);
            targetField = new JTextField();
            targetField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            urlPanel.add(targetField, BorderLayout.CENTER);

            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            JButton fullTestBtn = new JButton("🔍 Run Full Security Audit");
            fullTestBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            fullTestBtn.addActionListener(e -> runFullSecurityAudit());
            btnPanel.add(fullTestBtn);

            JButton quickTestBtn = new JButton("⚡ Quick Origin Test");
            quickTestBtn.addActionListener(e -> runQuickOriginTest());
            btnPanel.add(quickTestBtn);

            urlPanel.add(btnPanel, BorderLayout.EAST);
            topPanel.add(urlPanel, BorderLayout.SOUTH);

            add(topPanel, BorderLayout.NORTH);

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            JPanel resultPanel = new JPanel(new BorderLayout());
            resultPanel.add(new JLabel(" 📋 Security Audit Results:"), BorderLayout.NORTH);
            resultArea = new JTextArea();
            resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            resultArea.setEditable(false);
            resultPanel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
            split.setTopComponent(resultPanel);

            JPanel pocPanel = new JPanel(new BorderLayout());
            pocPanel.add(new JLabel(" 🎯 PoC Template (save as .html, open while logged into target):"), BorderLayout.NORTH);
            pocArea = new JTextArea();
            pocArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            pocArea.setEditable(false);
            pocPanel.add(new JScrollPane(pocArea), BorderLayout.CENTER);
            split.setBottomComponent(pocPanel);
            split.setDividerLocation(350);

            add(split, BorderLayout.CENTER);
        }

        void log(String msg) {
            SwingUtilities.invokeLater(() -> resultArea.append(msg + "\n"));
        }

        void runFullSecurityAudit() {
            String url = targetField.getText().trim();
            if (url.isEmpty()) {
                resultArea.setText("❌ Enter a WebSocket URL first.");
                return;
            }

            findings.clear();
            notes.clear();
            resultArea.setText("═══════════════════════════════════════════════════════\n");
            resultArea.append("  🔓 CSWSH SECURITY ANALYSIS\n");
            resultArea.append("  Target: " + url + "\n");
            resultArea.append("═══════════════════════════════════════════════════════\n\n");
            resultArea.append("⚠️  IMPORTANT: This tool performs static analysis only.\n");
            resultArea.append("   Java WebSocket client does NOT send:\n");
            resultArea.append("   • Cookies (browser sends automatically)\n");
            resultArea.append("   • Origin header (browser sends automatically)\n");
            resultArea.append("   \n");
            resultArea.append("   → Use the HTML PoC below for actual CSWSH testing!\n\n");

            new Thread(() -> {
                // Test 1: URL Analysis
                log("📌 ANALYSIS 1: URL Parameter Analysis\n" + "─".repeat(50));
                analyzeUrlForTokens(url);

                // Test 2: Connection test (just connectivity, not auth)
                log("\n📌 ANALYSIS 2: Connectivity Check\n" + "─".repeat(50));
                boolean canConnect = testConnectivity(url);

                // Test 3: Framework detection
                log("\n📌 ANALYSIS 3: Framework Detection\n" + "─".repeat(50));
                detectFramework(url);

                // Test 4: Security assessment
                log("\n📌 ANALYSIS 4: CSWSH Risk Assessment\n" + "─".repeat(50));
                assessCSWSHRisk(url);

                // Summary
                SwingUtilities.invokeLater(() -> {
                    resultArea.append("\n" + "═".repeat(55) + "\n");
                    resultArea.append("  📊 ANALYSIS SUMMARY\n");
                    resultArea.append("═".repeat(55) + "\n\n");

                    if (findings.isEmpty()) {
                        resultArea.append("🔍 No definitive CSWSH indicators found in static analysis.\n");
                        resultArea.append("   \n");
                        resultArea.append("   ⚠️  This does NOT mean the endpoint is secure!\n");
                        resultArea.append("   You MUST test with the HTML PoC to verify.\n");
                    } else {
                        resultArea.append("🔴 POTENTIAL CSWSH INDICATORS (" + findings.size() + "):\n\n");
                        for (int i = 0; i < findings.size(); i++) {
                            resultArea.append("  " + (i + 1) + ". " + findings.get(i) + "\n");
                        }
                    }

                    if (!notes.isEmpty()) {
                        resultArea.append("\n📝 NOTES:\n");
                        for (String note : notes) {
                            resultArea.append("  • " + note + "\n");
                        }
                    }

                    resultArea.append("\n" + "─".repeat(55) + "\n");
                    resultArea.append("🎯 HTML PoC generated below - USE THIS FOR ACTUAL TESTING\n");
                    resultArea.append("   1. Save the PoC as .html file\n");
                    resultArea.append("   2. Host it on a different domain (e.g., localhost:8000)\n");
                    resultArea.append("   3. Open while logged into the target application\n");
                    resultArea.append("   4. Click 'Start Hijack Test'\n");
                    resultArea.append("   5. If connection succeeds = VULNERABLE\n");

                    // Generate comprehensive PoC
                    generatePoC(url);
                });
            }).start();
        }

        void analyzeUrlForTokens(String url) {
            try {
                java.net.URI uri = new java.net.URI(url);
                String query = uri.getQuery();
                String path = uri.getPath();

                log("  URL: " + url);
                log("  Path: " + path);
                log("  Query: " + (query != null ? query : "(none)"));

                // Check for CSRF-like tokens in URL
                String[] csrfPatterns = {"token", "csrf", "nonce", "ticket", "auth", "key", "sid", "session"};
                boolean hasToken = false;
                boolean hasRandomString = false;

                String fullUrl = url.toLowerCase();
                for (String pattern : csrfPatterns) {
                    if (fullUrl.contains(pattern)) {
                        hasToken = true;
                        log("  🟢 Found potential token parameter: " + pattern);
                    }
                }

                // Check if URL has random/unique identifiers (potential CSRF tokens)
                if (url.matches(".*[a-f0-9]{32,}.*") || url.matches(".*[A-Za-z0-9_-]{20,}.*")) {
                    hasRandomString = true;
                    log("  🟢 URL contains long random string - likely a session/CSRF token");
                }

                if (hasToken || hasRandomString) {
                    log("  ");
                    log("  🟢 URL-based token detected - provides some CSWSH protection");
                    log("     However, verify the token is actually validated server-side");
                    notes.add("URL contains token-like parameter - test if it's validated");
                } else {
                    log("  ");
                    log("  🟡 No visible auth tokens in URL");
                    log("     This is common - auth may use cookies or first message");
                    notes.add("No URL token - auth may rely on cookies (test with PoC)");
                }

            } catch (Exception e) {
                log("  ❌ Error parsing URL: " + e.getMessage());
            }
        }

        boolean testConnectivity(String url) {
            try {
                WSConnection conn = new WSConnection();
                final boolean[] gotData = {false};
                final StringBuilder firstMsg = new StringBuilder();

                conn.setOnMessage(msg -> {
                    if (!gotData[0]) {
                        gotData[0] = true;
                        firstMsg.append(msg.length() > 100 ? msg.substring(0, 100) + "..." : msg);
                    }
                });

                log("  Testing basic connectivity (no cookies/Origin sent)...");
                boolean connected = conn.connect(url).get(5, TimeUnit.SECONDS);

                if (connected) {
                    log("  ✓ WebSocket endpoint is reachable");

                    // Wait for initial messages
                    Thread.sleep(2000);

                    if (gotData[0]) {
                        log("  ✓ Server sent initial data: " + firstMsg);

                        // Check if it looks like protocol handshake vs user data
                        String msg = firstMsg.toString();
                        if (msg.startsWith("0{") || msg.equals("o") || msg.startsWith("{\"type\":")) {
                            log("  ℹ️  This appears to be protocol handshake (normal)");
                        } else {
                            notes.add("Server sends data immediately - verify if it contains sensitive info");
                        }
                    } else {
                        log("  ✓ Connected but no data received yet (may need auth message)");
                    }

                    conn.disconnect();
                    log("  ");
                    log("  ⚠️  NOTE: This connectivity test does NOT prove CSWSH vulnerability!");
                    log("     Java client doesn't send cookies/Origin like browsers do.");
                    log("     Use the HTML PoC below for actual testing.");
                    return true;
                } else {
                    log("  ✗ Connection rejected or timed out");
                    notes.add("WebSocket endpoint not reachable - may require specific headers");
                    return false;
                }
            } catch (Exception e) {
                log("  ✗ Connection failed: " + e.getMessage());
                notes.add("Connection failed - endpoint may require authentication");
                return false;
            }
        }

        void detectFramework(String url) {
            String lowerUrl = url.toLowerCase();

            if (lowerUrl.contains("socket.io")) {
                log("  🔍 Socket.IO detected");
                log("     Default: allows all origins (check 'origins' config)");
                notes.add("Socket.IO - verify server 'origins' configuration");
            } else if (lowerUrl.contains("signalr")) {
                log("  🔍 SignalR detected");
                log("     CORS policy controlled by ASP.NET configuration");
                notes.add("SignalR - check ASP.NET CORS middleware");
            } else if (lowerUrl.contains("sockjs")) {
                log("  🔍 SockJS detected");
                log("     Has built-in CORS handling");
                notes.add("SockJS - verify origins whitelist");
            } else if (lowerUrl.contains("graphql")) {
                log("  🔍 GraphQL-WS detected");
                log("     Often requires 'graphql-ws' subprotocol");
                notes.add("GraphQL-WS - check subscription auth");
            } else if (lowerUrl.contains("cable") || lowerUrl.contains("actioncable")) {
                log("  🔍 Action Cable (Rails) detected");
                log("     Check allowed_request_origins config");
                notes.add("Action Cable - verify allowed_request_origins");
            } else {
                log("  ℹ️  No known framework detected in URL");
                log("     Custom WebSocket implementation");
            }
        }

        void assessCSWSHRisk(String url) {
            log("  CSWSH Risk Factors (browser-based attack):");
            log("  ");
            log("  When a browser connects to a WebSocket:");
            log("  ┌────────────────────────────────────────────────────────┐");
            log("  │ Cookies       → Sent automatically (SameSite=Lax/None)│");
            log("  │ Origin header → Sent automatically (can be validated) │");
            log("  │ Custom header → CANNOT be set cross-origin           │");
            log("  └────────────────────────────────────────────────────────┘");
            log("  ");
            log("  Common Auth Methods & CSWSH Risk:");
            log("  ");
            log("  🔴 HIGH RISK:");
            log("     • Cookies only (browser sends automatically)");
            log("     • No Origin validation");
            log("  ");
            log("  🟡 MEDIUM RISK:");
            log("     • URL token (if predictable/leaked)");
            log("     • Origin validated but allow wildcard/null");
            log("  ");
            log("  🟢 LOW RISK:");
            log("     • Custom header auth (can't be forged cross-origin)");
            log("     • First message auth + timeout");
            log("     • Strict Origin whitelist");
            log("  ");
            log("  ⚠️  Only the HTML PoC can determine actual vulnerability!");
        }

        void runQuickOriginTest() {
            String url = targetField.getText().trim();
            if (url.isEmpty()) {
                resultArea.setText("❌ Enter a WebSocket URL first.");
                return;
            }

            findings.clear();
            notes.clear();
            resultArea.setText("⚡ Quick Connectivity Test for " + url + "\n\n");
            resultArea.append("⚠️  NOTE: This test CANNOT verify CSWSH vulnerability!\n");
            resultArea.append("   Java client doesn't send cookies/Origin like browsers.\n");
            resultArea.append("   Use the HTML PoC for actual testing.\n\n");

            new Thread(() -> {
                try {
                    WSConnection conn = new WSConnection();
                    conn.setOnMessage(msg -> log("[MSG] " + (msg.length() > 200 ? msg.substring(0, 200) + "..." : msg)));
                    conn.setOnStatus(s -> log("[STATUS] " + s));

                    boolean connected = conn.connect(url).get(5, TimeUnit.SECONDS);
                    if (connected) {
                        log("\n✓ WebSocket endpoint is reachable");
                        log("  (This does NOT prove CSWSH vulnerability)");
                        Thread.sleep(3000);
                        conn.disconnect();
                    } else {
                        log("\n✗ Connection failed or rejected");
                    }
                } catch (Exception e) {
                    log("\n✗ Connection failed: " + e.getMessage());
                }

                SwingUtilities.invokeLater(() -> {
                    log("\n─────────────────────────────────────────────");
                    log("📋 HTML PoC generated below for browser testing");
                    generatePoC(url);
                });
            }).start();
        }

        void generatePoC(String url) {
            pocArea.setText(
                "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>CSWSH PoC - WebSocket Hijacking Test</title>\n" +
                "    <style>\n" +
                "        body { font-family: monospace; background: #1e1e1e; color: #ccc; padding: 20px; }\n" +
                "        .vulnerable { color: #ff4444; font-weight: bold; }\n" +
                "        .safe { color: #44ff44; }\n" +
                "        .data { color: #4488ff; }\n" +
                "        .info { color: #888; }\n" +
                "        #log { background: #2d2d2d; padding: 10px; margin-top: 10px; max-height: 400px; overflow-y: auto; border-radius: 4px; }\n" +
                "        .panel { background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 4px; }\n" +
                "        button { padding: 8px 16px; margin: 4px; cursor: pointer; }\n" +
                "        code { background: #444; padding: 2px 6px; border-radius: 3px; }\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <h2>🔓 Cross-Site WebSocket Hijacking (CSWSH) Test</h2>\n" +
                "    \n" +
                "    <div class=\"panel\">\n" +
                "        <strong>Target:</strong> <code>" + url + "</code><br><br>\n" +
                "        <strong>Instructions:</strong><br>\n" +
                "        1. Host this file on a DIFFERENT domain than the target<br>\n" +
                "        2. Log into the target application in another tab<br>\n" +
                "        3. Click \"Start Hijack Test\" below<br>\n" +
                "        4. <span class=\"vulnerable\">If connection succeeds = VULNERABLE</span><br>\n" +
                "        5. <span class=\"safe\">If connection fails = Protected</span>\n" +
                "    </div>\n" +
                "    \n" +
                "    <button onclick=\"startTest()\">▶ Start Hijack Test</button>\n" +
                "    <button onclick=\"sendTestMessage()\">📤 Send Test Message</button>\n" +
                "    <button onclick=\"ws && ws.close()\">⏹ Disconnect</button>\n" +
                "    <button onclick=\"log.innerHTML=''\">🗑 Clear Log</button>\n" +
                "    \n" +
                "    <div id=\"log\"></div>\n" +
                "    \n" +
                "    <script>\n" +
                "    var ws = null;\n" +
                "    var log = document.getElementById('log');\n" +
                "    \n" +
                "    function addLog(msg, cls) {\n" +
                "        log.innerHTML += '<div class=\"' + (cls||'info') + '\">[' + new Date().toLocaleTimeString() + '] ' + msg + '</div>';\n" +
                "        log.scrollTop = log.scrollHeight;\n" +
                "    }\n" +
                "    \n" +
                "    function startTest() {\n" +
                "        if (ws && ws.readyState === 1) {\n" +
                "            addLog('Already connected. Disconnect first.', 'info');\n" +
                "            return;\n" +
                "        }\n" +
                "        \n" +
                "        addLog('─────────────────────────────────────────');\n" +
                "        addLog('Starting Cross-Site WebSocket Hijacking test...');\n" +
                "        addLog('Your Origin: ' + window.location.origin);\n" +
                "        addLog('Target: " + url + "');\n" +
                "        addLog('Browser will send cookies automatically (if SameSite allows)');\n" +
                "        addLog('─────────────────────────────────────────');\n" +
                "        \n" +
                "        try {\n" +
                "            ws = new WebSocket('" + url + "');\n" +
                "            \n" +
                "            ws.onopen = function() {\n" +
                "                addLog('', 'vulnerable');\n" +
                "                addLog('🔴 VULNERABLE - Connection accepted from cross-origin!', 'vulnerable');\n" +
                "                addLog('The server did not validate the Origin header.', 'vulnerable');\n" +
                "                addLog('Session cookies were sent with this request.', 'vulnerable');\n" +
                "                addLog('', 'vulnerable');\n" +
                "                addLog('Impact: Attacker can hijack authenticated WebSocket sessions');\n" +
                "            };\n" +
                "            \n" +
                "            ws.onmessage = function(e) {\n" +
                "                var data = e.data;\n" +
                "                if (data.length > 500) data = data.substring(0, 500) + '...';\n" +
                "                addLog('📨 Data received: ' + data, 'data');\n" +
                "            };\n" +
                "            \n" +
                "            ws.onerror = function(e) {\n" +
                "                addLog('🟢 Connection blocked - server may validate Origin', 'safe');\n" +
                "                addLog('Check browser console (F12) for more details', 'info');\n" +
                "            };\n" +
                "            \n" +
                "            ws.onclose = function(e) {\n" +
                "                if (e.code === 1006) {\n" +
                "                    addLog('Connection rejected (code 1006) - likely Origin validation', 'safe');\n" +
                "                } else {\n" +
                "                    addLog('Connection closed: code=' + e.code + ' reason=' + (e.reason || 'none'));\n" +
                "                }\n" +
                "            };\n" +
                "        } catch(e) {\n" +
                "            addLog('Exception: ' + e.message, 'safe');\n" +
                "        }\n" +
                "    }\n" +
                "    \n" +
                "    function sendTestMessage() {\n" +
                "        if (!ws || ws.readyState !== 1) {\n" +
                "            addLog('Not connected - start test first');\n" +
                "            return;\n" +
                "        }\n" +
                "        // Customize this payload for your target\n" +
                "        var payload = JSON.stringify({action: 'get_user_data', test: true});\n" +
                "        ws.send(payload);\n" +
                "        addLog('📤 Sent: ' + payload);\n" +
                "    }\n" +
                "    \n" +
                "    addLog('Ready. Click \"Start Hijack Test\" to begin.');\n" +
                "    addLog('Make sure you are logged into the target application.');\n" +
                "    </script>\n" +
                "</body>\n" +
                "</html>"
            );
        }
    }

    // ==================== QUICK TESTS PANEL ====================

    private class QuickTestPanel extends JPanel {
        private JTextField urlField;
        private JTextArea logArea;
        private String targetUrl = "";
        private java.util.concurrent.atomic.AtomicInteger responseCount = new java.util.concurrent.atomic.AtomicInteger(0);

        QuickTestPanel() {
            setLayout(new BorderLayout(8, 8));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel topPanel = new JPanel(new BorderLayout(8, 0));
            topPanel.add(new JLabel("URL: "), BorderLayout.WEST);
            urlField = new JTextField();
            urlField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            topPanel.add(urlField, BorderLayout.CENTER);

            JButton clearBtn = new JButton("Clear Log");
            clearBtn.addActionListener(e -> logArea.setText(""));
            topPanel.add(clearBtn, BorderLayout.EAST);
            add(topPanel, BorderLayout.NORTH);

            // Buttons panel
            JPanel buttonsPanel = new JPanel();
            buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.Y_AXIS));
            buttonsPanel.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0));

            // Auth Bypass
            JPanel authPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            authPanel.setBorder(BorderFactory.createTitledBorder("Auth Bypass — Connect without auth, send action"));
            JTextField authAction = new JTextField("42[\"admin:list_users\",{}]", 40);
            authAction.setFont(new Font("Monospaced", Font.PLAIN, 11));
            authPanel.add(authAction);
            JButton authBtn = new JButton("Test Auth Bypass");
            authBtn.addActionListener(e -> runQuickTest(authAction.getText(), false));
            authPanel.add(authBtn);
            buttonsPanel.add(authPanel);

            // Race Condition
            JPanel racePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            racePanel.setBorder(BorderFactory.createTitledBorder("Race Condition — Rapid fire same message"));
            JTextField raceMsg = new JTextField("42[\"redeem_coupon\",{\"code\":\"FREEBIE\"}]", 30);
            raceMsg.setFont(new Font("Monospaced", Font.PLAIN, 11));
            racePanel.add(raceMsg);
            racePanel.add(new JLabel("Count:"));
            JSpinner raceCount = new JSpinner(new SpinnerNumberModel(20, 1, 1000, 5));
            racePanel.add(raceCount);
            JButton raceBtn = new JButton("Fire All");
            raceBtn.addActionListener(e -> runRaceTest(raceMsg.getText(), (int) raceCount.getValue()));
            racePanel.add(raceBtn);
            buttonsPanel.add(racePanel);

            // Socket.IO Event Enumeration
            JPanel enumPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            enumPanel.setBorder(BorderFactory.createTitledBorder("Socket.IO Enumeration — Try hidden events/namespaces"));
            JButton enumEventsBtn = new JButton("Enumerate Events (" + Payloads.ALL.get("Socket.IO Events").size() + ")");
            enumEventsBtn.addActionListener(e -> enumerateSocketIO("events"));
            enumPanel.add(enumEventsBtn);
            JButton enumNsBtn = new JButton("Enumerate Namespaces (" + Payloads.ALL.get("Socket.IO Namespaces").size() + ")");
            enumNsBtn.addActionListener(e -> enumerateSocketIO("namespaces"));
            enumPanel.add(enumNsBtn);
            buttonsPanel.add(enumPanel);

            add(buttonsPanel, BorderLayout.WEST);

            // Log area
            logArea = new JTextArea();
            logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            logArea.setEditable(false);
            add(new JScrollPane(logArea), BorderLayout.CENTER);
        }

        void setTargetUrl(String url) {
            this.targetUrl = url;
            urlField.setText(url);
        }

        private String timestamp() {
            return java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
        }

        void runQuickTest(String message, boolean sendAuth) {
            String url = urlField.getText().trim();
            responseCount.set(0);

            logArea.append("\n╔══════════════════════════════════════════════════════════════════════╗\n");
            logArea.append("║                       AUTH BYPASS TEST                                ║\n");
            logArea.append("╚══════════════════════════════════════════════════════════════════════╝\n");
            logArea.append("[" + timestamp() + "] Target URL: " + url + "\n");
            logArea.append("[" + timestamp() + "] Test: Connecting WITHOUT authentication cookies/headers\n");
            logArea.append("─────────────────────────────────────────────────────────────────────────\n");

            new Thread(() -> {
                WSConnection conn = new WSConnection();
                conn.setOnMessage(msg -> SwingUtilities.invokeLater(() -> {
                    int num = responseCount.incrementAndGet();
                    logArea.append("[" + timestamp() + "] ↓ RESPONSE #" + num + "\n");
                    logArea.append("    Length: " + msg.length() + " bytes\n");
                    logArea.append("    Data: " + msg + "\n");
                    logArea.append("─────────────────────────────────────────────────────────────────────────\n");
                }));
                try {
                    log("[" + timestamp() + "] Connecting to WebSocket...");
                    conn.connect(url).get(5, TimeUnit.SECONDS);
                    log("[" + timestamp() + "] ✓ Connected successfully (no auth!)");
                    log("[" + timestamp() + "] ");
                    log("[" + timestamp() + "] ↑ REQUEST (Auth Bypass Attempt)");
                    log("    Payload: " + message);
                    log("    Length: " + message.length() + " bytes");
                    log("─────────────────────────────────────────────────────────────────────────");
                    conn.send(message);
                    log("[" + timestamp() + "] Waiting for server response (3 seconds)...");
                    Thread.sleep(3000);
                    conn.disconnect();
                    log("");
                    log("╔══════════════════════════════════════════════════════════════════════╗");
                    log("║ TEST COMPLETE                                                         ║");
                    log("╚══════════════════════════════════════════════════════════════════════╝");
                    log("Total Responses Received: " + responseCount.get());
                    log("");
                    log("ANALYSIS:");
                    if (responseCount.get() > 0) {
                        log("  ⚠️  Server responded! Check if action was executed without auth.");
                        log("  → If server returned data/success: VULNERABLE to Auth Bypass!");
                        log("  → If server returned error/denied: Properly protected.");
                    } else {
                        log("  ℹ️  No response received.");
                        log("  → Server may have dropped unauthenticated connection.");
                    }
                    log("\n");
                } catch (Exception e) {
                    log("[" + timestamp() + "] ✗ FAILED: " + e.getMessage());
                    log("  → This could mean the connection requires authentication.");
                    log("\n");
                }
            }).start();
        }

        void runRaceTest(String message, int count) {
            String url = urlField.getText().trim();
            responseCount.set(0);

            logArea.append("\n╔══════════════════════════════════════════════════════════════════════╗\n");
            logArea.append("║                      RACE CONDITION TEST                              ║\n");
            logArea.append("╚══════════════════════════════════════════════════════════════════════╝\n");
            logArea.append("[" + timestamp() + "] Target URL: " + url + "\n");
            logArea.append("[" + timestamp() + "] Test: Sending " + count + " rapid-fire identical requests\n");
            logArea.append("[" + timestamp() + "] Payload: " + message + "\n");
            logArea.append("─────────────────────────────────────────────────────────────────────────\n");

            new Thread(() -> {
                WSConnection conn = new WSConnection();
                List<String> responses = Collections.synchronizedList(new ArrayList<>());

                conn.setOnMessage(msg -> {
                    int num = responseCount.incrementAndGet();
                    responses.add(msg);
                    SwingUtilities.invokeLater(() -> {
                        // Don't skip pings for visibility
                        logArea.append("[" + timestamp() + "] ↓ RESPONSE #" + num + ": " + msg + "\n");
                    });
                });

                try {
                    log("[" + timestamp() + "] Connecting...");
                    conn.connect(url).get(5, TimeUnit.SECONDS);
                    log("[" + timestamp() + "] ✓ Connected");
                    Thread.sleep(500);

                    log("");
                    log("[" + timestamp() + "] ═══ FIRING " + count + " REQUESTS ═══");
                    log("");

                    long start = System.currentTimeMillis();
                    for (int i = 0; i < count; i++) {
                        conn.send(message);
                        log("[" + timestamp() + "] ↑ REQUEST #" + (i + 1) + " SENT");
                    }
                    long elapsed = System.currentTimeMillis() - start;

                    log("");
                    log("[" + timestamp() + "] All " + count + " requests sent in " + elapsed + "ms");
                    log("[" + timestamp() + "] Rate: " + String.format("%.2f", (count * 1000.0 / elapsed)) + " req/sec");
                    log("[" + timestamp() + "] Waiting for responses (3 seconds)...");
                    log("─────────────────────────────────────────────────────────────────────────");

                    Thread.sleep(3000);
                    conn.disconnect();

                    log("");
                    log("╔══════════════════════════════════════════════════════════════════════╗");
                    log("║ TEST COMPLETE                                                         ║");
                    log("╚══════════════════════════════════════════════════════════════════════╝");
                    log("Requests Sent: " + count);
                    log("Responses Received: " + responseCount.get());
                    log("");
                    log("ANALYSIS:");

                    // Analyze for race condition indicators
                    Map<String, Integer> responseCounts = new HashMap<>();
                    for (String r : responses) {
                        responseCounts.merge(r, 1, Integer::sum);
                    }

                    if (responseCounts.size() > 0) {
                        log("  Unique response types: " + responseCounts.size());
                        for (Map.Entry<String, Integer> entry : responseCounts.entrySet()) {
                            String respPreview = entry.getKey().length() > 60
                                ? entry.getKey().substring(0, 60) + "..."
                                : entry.getKey();
                            log("    → \"" + respPreview + "\" (×" + entry.getValue() + ")");
                        }
                        log("");
                        if (responseCount.get() == count) {
                            log("  ⚠️  All requests got responses! Check if action executed multiple times.");
                            log("  → For coupons/credits: Was the benefit applied " + count + " times?");
                        } else if (responseCount.get() > count) {
                            log("  ⚠️  More responses than requests! Server may be vulnerable.");
                        } else {
                            log("  ℹ️  Some requests may have been rate-limited or deduplicated.");
                        }
                    }
                    log("\n");
                } catch (Exception e) {
                    log("[" + timestamp() + "] ✗ FAILED: " + e.getMessage() + "\n");
                }
            }).start();
        }

        void enumerateSocketIO(String type) {
            String url = urlField.getText().trim();
            List<String> items = type.equals("events")
                ? Payloads.ALL.get("Socket.IO Events")
                : Payloads.ALL.get("Socket.IO Namespaces");

            responseCount.set(0);

            logArea.append("\n╔══════════════════════════════════════════════════════════════════════╗\n");
            logArea.append("║              SOCKET.IO " + type.toUpperCase() + " ENUMERATION                          ║\n");
            logArea.append("╚══════════════════════════════════════════════════════════════════════╝\n");
            logArea.append("[" + timestamp() + "] Target URL: " + url + "\n");
            logArea.append("[" + timestamp() + "] Testing " + items.size() + " " + type + "\n");
            logArea.append("─────────────────────────────────────────────────────────────────────────\n");

            new Thread(() -> {
                WSConnection conn = new WSConnection();
                List<String[]> findings = Collections.synchronizedList(new ArrayList<>());
                final String[] lastSent = {""};

                conn.setOnMessage(msg -> {
                    int num = responseCount.incrementAndGet();
                    // Skip pings/pongs but log everything else
                    if (!msg.equals("2") && !msg.equals("3")) {
                        findings.add(new String[]{lastSent[0], msg});
                        SwingUtilities.invokeLater(() -> {
                            logArea.append("[" + timestamp() + "] ↓ RESPONSE #" + num + ": " + msg + "\n");
                        });
                    }
                });

                try {
                    log("[" + timestamp() + "] Connecting...");
                    conn.connect(url).get(5, TimeUnit.SECONDS);
                    log("[" + timestamp() + "] ✓ Connected");
                    Thread.sleep(1000);
                    log("");

                    int idx = 0;
                    for (String item : items) {
                        idx++;
                        String frame;
                        if (type.equals("events")) {
                            frame = "42[\"" + item + "\",{}]";
                        } else {
                            frame = "40" + item + ",";
                        }
                        lastSent[0] = frame;
                        conn.send(frame);
                        log("[" + timestamp() + "] ↑ #" + idx + "/" + items.size() + " " + frame);
                        Thread.sleep(200);
                    }

                    log("");
                    log("[" + timestamp() + "] Waiting for final responses...");
                    Thread.sleep(3000);
                    conn.disconnect();

                    log("");
                    log("╔══════════════════════════════════════════════════════════════════════╗");
                    log("║ ENUMERATION COMPLETE                                                  ║");
                    log("╚══════════════════════════════════════════════════════════════════════╝");
                    log("Total " + type + " tested: " + items.size());
                    log("Responses received: " + responseCount.get());
                    log("");

                    if (findings.size() > 0) {
                        log("FINDINGS - Server responded to these " + type + ":");
                        for (String[] f : findings) {
                            log("  Request: " + f[0]);
                            log("  Response: " + f[1]);
                            log("  ─────");
                        }
                        log("");
                        log("⚠️  Review responses above for valid/hidden " + type + "!");
                    } else {
                        log("ℹ️  No interesting responses received.");
                    }
                    log("\n");
                } catch (Exception e) {
                    log("[" + timestamp() + "] ✗ FAILED: " + e.getMessage() + "\n");
                }
            }).start();
        }

        void log(String msg) {
            SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
        }
    }

    // ==================== INTERCEPT ACTION MODEL ====================

    private static class InterceptAction {
        final String modifiedPayload;  // null = drop

        InterceptAction(String modifiedPayload) {
            this.modifiedPayload = modifiedPayload;
        }
    }
}
