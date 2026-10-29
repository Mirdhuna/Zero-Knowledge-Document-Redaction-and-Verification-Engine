package com.zeroknowledge.frontend;

import com.zeroknowledge.model.OperationRecord;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

/**
 * Activity and Audit Workspace:
 * Provides an immutable local audit log of all security-sensitive operations
 * with filtering and summary metrics.
 */
public class AuditPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JComboBox<String> operationFilterCombo;
    private JComboBox<String> statusFilterCombo;
    private JLabel totalRecordsLabel;

    private JTable auditTable;
    private DefaultTableModel auditModel;
    private JScrollPane tableScrollPane;
    private JPanel emptyStatePanel;

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public AuditPanel(BackendContext context, Consumer<String> navigationConsumer) {
        this.context = context;
        this.navigationConsumer = navigationConsumer;

        setLayout(new BorderLayout(0, 16));
        setBackground(ThemeManager.WORKSPACE_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
        refreshAuditTable();
    }

    private void initUI() {
        JPanel contentContainer = new JPanel();
        contentContainer.setLayout(new BoxLayout(contentContainer, BoxLayout.Y_AXIS));
        contentContainer.setOpaque(false);

        // Header
        contentContainer.add(createHeaderPanel());
        contentContainer.add(Box.createVerticalStrut(16));

        // Audit Table Card
        contentContainer.add(createTableCard());

        add(contentContainer, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel title = new JLabel("Audit & Activity Log");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel("Review local cryptographic events, redaction executions, and verification audits.");
        desc.setFont(ThemeManager.FONT_REGULAR);
        desc.setForeground(ThemeManager.TEXT_SECONDARY);

        left.add(title);
        left.add(desc);

        JButton backBtn = ThemeManager.createSecondaryButton("← Dashboard");
        backBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_DASHBOARD));

        panel.add(left, BorderLayout.WEST);
        panel.add(backBtn, BorderLayout.EAST);
        return panel;
    }

    private JPanel createTableCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        // Filter Bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        filterBar.setOpaque(false);

        JLabel opLbl = new JLabel("Operation:");
        opLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        operationFilterCombo = ThemeManager.createComboBox();
        String[] ops = new String[]{
                "All Operations",
                "DOCUMENT_SCAN",
                "DOCUMENT_REDACT",
                "HASH_CALCULATION",
                "KEY_GENERATION",
                "KEY_LOAD",
                "KEY_EXPORT",
                "DOCUMENT_SIGN",
                "SIGNATURE_VERIFY",
                "ACCESS_CHECK",
                "UNSUPPORTED_PDF_OPERATION"
        };
        for (String op : ops) operationFilterCombo.addItem(op);
        operationFilterCombo.addActionListener(e -> refreshAuditTable());

        JLabel stLbl = new JLabel("Status:");
        stLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        statusFilterCombo = ThemeManager.createComboBox();
        statusFilterCombo.addItem("All Statuses");
        statusFilterCombo.addItem("SUCCESS");
        statusFilterCombo.addItem("FAILED");
        statusFilterCombo.addActionListener(e -> refreshAuditTable());

        JButton refreshBtn = ThemeManager.createSecondaryButton("Refresh");
        refreshBtn.addActionListener(e -> refreshAuditTable());

        JButton clearBtn = ThemeManager.createDangerButton("Clear Log");
        clearBtn.addActionListener(e -> handleClearLog());

        totalRecordsLabel = new JLabel("0 records");
        totalRecordsLabel.setFont(ThemeManager.FONT_SMALL_BOLD);
        totalRecordsLabel.setForeground(ThemeManager.TEXT_SECONDARY);

        filterBar.add(opLbl);
        filterBar.add(operationFilterCombo);
        filterBar.add(stLbl);
        filterBar.add(statusFilterCombo);
        filterBar.add(refreshBtn);
        filterBar.add(clearBtn);
        filterBar.add(totalRecordsLabel);

        card.add(filterBar, BorderLayout.NORTH);

        // Table
        String[] columns = {"Timestamp", "Operation", "Document / Target", "Result", "Technical Details"};
        auditModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        auditTable = new JTable(auditModel);
        ThemeManager.styleTable(auditTable);
        auditTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        auditTable.getColumnModel().getColumn(1).setPreferredWidth(130);
        auditTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        auditTable.getColumnModel().getColumn(3).setPreferredWidth(90);
        auditTable.getColumnModel().getColumn(4).setPreferredWidth(340);

        auditTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value != null) {
                    String str = value.toString();
                    if ("SUCCESS".equalsIgnoreCase(str)) {
                        c.setForeground(ThemeManager.SUCCESS_GREEN);
                        setFont(ThemeManager.FONT_SMALL_BOLD);
                    } else {
                        c.setForeground(ThemeManager.DANGER_RED);
                        setFont(ThemeManager.FONT_SMALL_BOLD);
                    }
                }
                return c;
            }
        });

        tableScrollPane = new JScrollPane(auditTable);
        tableScrollPane.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScrollPane.getViewport().setBackground(ThemeManager.CARD_BG);

        // Empty state
        emptyStatePanel = new JPanel(new GridBagLayout());
        emptyStatePanel.setOpaque(false);
        JLabel emptyLbl = new JLabel("No audit events match the selected criteria.");
        emptyLbl.setFont(ThemeManager.FONT_REGULAR);
        emptyLbl.setForeground(ThemeManager.TEXT_MUTED);
        emptyStatePanel.add(emptyLbl);

        card.add(tableScrollPane, BorderLayout.CENTER);
        return card;
    }

    public void refreshAuditTable() {
        String opSel = (String) operationFilterCombo.getSelectedItem();
        String stSel = (String) statusFilterCombo.getSelectedItem();

        List<OperationRecord> records = context.getAuditService().getRecords();
        auditModel.setRowCount(0);

        int displayedCount = 0;
        for (OperationRecord r : records) {
            boolean matchOp = (opSel == null || opSel.equals("All Operations") || r.getOperationType().name().equals(opSel));
            boolean matchStatus = (stSel == null || stSel.equals("All Statuses") ||
                    (stSel.equals("SUCCESS") && r.isSuccess()) ||
                    (stSel.equals("FAILED") && !r.isSuccess()));

            if (matchOp && matchStatus) {
                auditModel.addRow(new Object[]{
                        TIME_FORMATTER.format(r.getTimestamp()),
                        r.getOperationType().name(),
                        r.getDocumentIdentifier(),
                        r.isSuccess() ? "SUCCESS" : "FAILED",
                        r.getDetails()
                });
                displayedCount++;
            }
        }

        if (displayedCount == 0) {
            tableScrollPane.setViewportView(emptyStatePanel);
        } else {
            tableScrollPane.setViewportView(auditTable);
        }

        totalRecordsLabel.setText(displayedCount + " record(s) displayed");
    }

    private void handleClearLog() {
        boolean confirm = DialogManager.showConfirmation(
                this,
                "Confirm Clear Audit Log",
                "Are you sure you want to clear the local audit log history?\n" +
                        "This will reset all recorded activity metrics.",
                "Clear History"
        );
        if (confirm) {
            context.getAuditService().clearMemoryRecords();
            refreshAuditTable();
            DialogManager.showInfo(this, "Audit Cleared", "The local audit history has been cleared.");
        }
    }
}
