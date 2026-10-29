package com.zeroknowledge.frontend;

import com.zeroknowledge.model.OperationRecord;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

/**
 * Dashboard screen providing an overview of recent operations, real security metrics,
 * cryptographic key status, and quick launch actions.
 */
public class DashboardPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JLabel scannedCountLabel;
    private JLabel redactedCountLabel;
    private JLabel verifiedCountLabel;
    private JLabel keyStatusLabel;
    private JTable recentActivityTable;
    private DefaultTableModel activityModel;
    private JPanel emptyStatePanel;
    private JScrollPane tableScrollPane;

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public DashboardPanel(BackendContext context, Consumer<String> navigationConsumer) {
        this.context = context;
        this.navigationConsumer = navigationConsumer;

        setLayout(new BorderLayout(0, 20));
        setBackground(ThemeManager.WORKSPACE_BG);
        setBorder(new EmptyBorder(24, 28, 24, 28));

        initUI();
        refreshData();
    }

    private void initUI() {
        // Top Banner / Welcome Card
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setOpaque(false);

        JPanel welcomeCard = ThemeManager.createCardPanel();
        welcomeCard.setLayout(new BorderLayout(16, 0));

        JPanel textGroup = new JPanel();
        textGroup.setLayout(new BoxLayout(textGroup, BoxLayout.Y_AXIS));
        textGroup.setOpaque(false);

        JLabel titleLabel = new JLabel("Zero-Knowledge Document Redaction & Verification Engine");
        titleLabel.setFont(ThemeManager.FONT_TITLE);
        titleLabel.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel subtitleLabel = new JLabel(
                "Detect sensitive PII/secrets, confirm redactions, generate versioned detached RSA signatures, and verify document integrity."
        );
        subtitleLabel.setFont(ThemeManager.FONT_REGULAR);
        subtitleLabel.setForeground(ThemeManager.TEXT_SECONDARY);
        subtitleLabel.setBorder(new EmptyBorder(4, 0, 0, 0));

        textGroup.add(titleLabel);
        textGroup.add(subtitleLabel);

        // Prominent Action Buttons
        JPanel actionBtnGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionBtnGroup.setOpaque(false);

        JButton redactBtn = ThemeManager.createPrimaryButton("Redact Document");
        redactBtn.setToolTipText("Scan a document and sanitize sensitive information");
        redactBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_REDACTION));

        JButton verifyBtn = ThemeManager.createSecondaryButton("Verify Document");
        verifyBtn.setToolTipText("Check cryptographic authenticity and detached signature");
        verifyBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_VERIFICATION));

        actionBtnGroup.add(redactBtn);
        actionBtnGroup.add(verifyBtn);

        welcomeCard.add(textGroup, BorderLayout.CENTER);
        welcomeCard.add(actionBtnGroup, BorderLayout.EAST);
        topContainer.add(welcomeCard);
        topContainer.add(Box.createVerticalStrut(14));

        // User-Friendly Getting Started Walkthrough Card
        JPanel guideCard = ThemeManager.createCardPanel();
        guideCard.setLayout(new BorderLayout(0, 10));

        JPanel guideHeader = new JPanel(new BorderLayout());
        guideHeader.setOpaque(false);
        JLabel guideTitle = new JLabel("Quick Start: The 3-Step Zero-Knowledge Workflow");
        guideTitle.setFont(ThemeManager.FONT_HEADER);
        guideTitle.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel guideBadge = ThemeManager.createBadge("New User Guide", ThemeManager.SUCCESS_BG, ThemeManager.SUCCESS_GREEN);
        guideHeader.add(guideTitle, BorderLayout.WEST);
        guideHeader.add(guideBadge, BorderLayout.EAST);
        guideCard.add(guideHeader, BorderLayout.NORTH);

        JPanel stepsRow = new JPanel(new GridLayout(1, 3, 16, 0));
        stepsRow.setOpaque(false);

        stepsRow.add(createStepGuideBlock(
                1,
                "1. Redact Document",
                "Select a PDF, TXT, or CSV file. The engine scans for PII and sensitive data, lets you choose what to mask, and saves a clean sanitized copy."
        ));
        stepsRow.add(createStepGuideBlock(
                2,
                "2. Detached Digital Sign",
                "The engine signs the exact bytes of your sanitized document with SHA256withRSA, generating a companion .zksig signature file."
        ));
        stepsRow.add(createStepGuideBlock(
                3,
                "3. Verify Authenticity",
                "Verifiers inspect the document and .zksig file against your public key to prove integrity without exposing redacted confidential content."
        ));

        guideCard.add(stepsRow, BorderLayout.CENTER);
        topContainer.add(guideCard);
        topContainer.add(Box.createVerticalStrut(14));

        // Metric Counter Cards (4 columns)
        JPanel statsGrid = new JPanel(new GridLayout(1, 4, 16, 0));
        statsGrid.setOpaque(false);

        scannedCountLabel = new JLabel("0");
        redactedCountLabel = new JLabel("0");
        verifiedCountLabel = new JLabel("0");
        keyStatusLabel = new JLabel("None");

        statsGrid.add(createMetricCard("Scanned Documents", scannedCountLabel, "Locally inspected", ThemeManager.PRIMARY_BLUE));
        statsGrid.add(createMetricCard("Redacted Documents", redactedCountLabel, "Sanitized & exported", ThemeManager.SUCCESS_GREEN));
        statsGrid.add(createMetricCard("Verified Signatures", verifiedCountLabel, "Integrity confirmed", new Color(13, 148, 136)));
        statsGrid.add(createMetricCard("Active RSA Key", keyStatusLabel, "Current signing identity", ThemeManager.WARNING_AMBER));

        topContainer.add(statsGrid);
        add(topContainer, BorderLayout.NORTH);

        // Center Content Area: Split between Recent Activity and Security Architecture Note
        JPanel centerContainer = new JPanel(new BorderLayout(16, 0));
        centerContainer.setOpaque(false);

        // Activity Card
        JPanel activityCard = ThemeManager.createCardPanel();
        activityCard.setLayout(new BorderLayout(0, 12));

        JPanel actHeader = new JPanel(new BorderLayout());
        actHeader.setOpaque(false);
        JLabel actTitle = new JLabel("Recent Activity");
        actTitle.setFont(ThemeManager.FONT_HEADER);
        actTitle.setForeground(ThemeManager.TEXT_PRIMARY);

        JButton viewAllBtn = new JButton("View Full Audit Log →");
        viewAllBtn.setFont(ThemeManager.FONT_SMALL_BOLD);
        viewAllBtn.setForeground(ThemeManager.PRIMARY_BLUE);
        viewAllBtn.setContentAreaFilled(false);
        viewAllBtn.setBorderPainted(false);
        viewAllBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        viewAllBtn.addActionListener(e -> navigationConsumer.accept(MainFrame.CARD_AUDIT));

        actHeader.add(actTitle, BorderLayout.WEST);
        actHeader.add(viewAllBtn, BorderLayout.EAST);
        activityCard.add(actHeader, BorderLayout.NORTH);

        // Activity Table
        String[] columns = {"Timestamp", "Operation", "Document / Target", "Result", "Technical Details"};
        activityModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        recentActivityTable = new JTable(activityModel);
        ThemeManager.styleTable(recentActivityTable);
        recentActivityTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        recentActivityTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        recentActivityTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        recentActivityTable.getColumnModel().getColumn(3).setPreferredWidth(90);
        recentActivityTable.getColumnModel().getColumn(4).setPreferredWidth(260);

        tableScrollPane = new JScrollPane(recentActivityTable);
        tableScrollPane.setBorder(BorderFactory.createLineBorder(ThemeManager.CARD_BORDER));
        tableScrollPane.getViewport().setBackground(ThemeManager.CARD_BG);

        // Empty state for Activity
        emptyStatePanel = new JPanel(new GridBagLayout());
        emptyStatePanel.setOpaque(false);
        JLabel emptyLabel = new JLabel("No operations recorded yet. Start by scanning or verifying a document.");
        emptyLabel.setFont(ThemeManager.FONT_REGULAR);
        emptyLabel.setForeground(ThemeManager.TEXT_MUTED);
        emptyStatePanel.add(emptyLabel);

        activityCard.add(tableScrollPane, BorderLayout.CENTER);
        centerContainer.add(activityCard, BorderLayout.CENTER);

        // Right Sidebar: Security Assurance Card
        JPanel rightInfoCard = ThemeManager.createCardPanel();
        rightInfoCard.setPreferredSize(new Dimension(310, 0));
        rightInfoCard.setLayout(new BoxLayout(rightInfoCard, BoxLayout.Y_AXIS));

        JLabel infoHeader = new JLabel("Security Architecture");
        infoHeader.setFont(ThemeManager.FONT_HEADER);
        infoHeader.setForeground(ThemeManager.TEXT_PRIMARY);

        rightInfoCard.add(infoHeader);
        rightInfoCard.add(Box.createVerticalStrut(12));

        rightInfoCard.add(createSecurityBullet("Pure-JDK Content Redaction",
                "PDF, TXT & CSV formats support deep byte-level sanitization. Compressed PDF streams are decompressed, redacted, and rebuilt with exact xref offsets."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Deterministic SHA-256",
                "Cryptographic digests are calculated via streaming MessageDigest over exact file bytes before and after redaction."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Detached RSA Signatures",
                "Documents are signed via standard SHA256withRSA. Detached .zksig files record metadata without modifying source files."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Auditable Privacy",
                "Audit logs record operations with automatic secret scrubbing. Raw sensitive values are never logged or exported."));

        centerContainer.add(rightInfoCard, BorderLayout.EAST);
        add(centerContainer, BorderLayout.CENTER);
    }

    private JPanel createStepGuideBlock(int step, String title, String description) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);
        p.setBorder(new CompoundBorder(
                BorderFactory.createLineBorder(ThemeManager.CARD_BORDER, 1, true),
                new EmptyBorder(12, 14, 12, 14)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(ThemeManager.FONT_SUBHEADER);
        titleLbl.setForeground(ThemeManager.PRIMARY_BLUE);

        JLabel descLbl = new JLabel("<html><body style='width: 200px; color: #334155; line-height: 1.4;'>"
                + description + "</body></html>");
        descLbl.setFont(ThemeManager.FONT_SMALL);

        p.add(titleLbl);
        p.add(Box.createVerticalStrut(4));
        p.add(descLbl);
        return p;
    }

    private JPanel createMetricCard(String title, JLabel valueLabel, String subtext, Color accent) {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 6));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        titleLbl.setForeground(ThemeManager.TEXT_SECONDARY);

        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 22));
        valueLabel.setForeground(accent);

        JLabel subLbl = new JLabel(subtext);
        subLbl.setFont(ThemeManager.FONT_SMALL);
        subLbl.setForeground(ThemeManager.TEXT_MUTED);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        card.add(subLbl, BorderLayout.SOUTH);
        return card;
    }

    private JPanel createSecurityBullet(String title, String desc) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);

        JLabel t = new JLabel("• " + title);
        t.setFont(ThemeManager.FONT_SMALL_BOLD);
        t.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel d = new JLabel("<html><body style='width: 250px;'>" + desc + "</body></html>");
        d.setFont(ThemeManager.FONT_SMALL);
        d.setForeground(ThemeManager.TEXT_SECONDARY);
        d.setBorder(new EmptyBorder(2, 10, 0, 0));

        p.add(t);
        p.add(d);
        return p;
    }

    /**
     * Refreshes dashboard statistics and recent activity table from the real backend AuditService.
     */
    public void refreshData() {
        List<OperationRecord> allRecords = context.getAuditService().getRecords();

        int scanned = 0;
        int redacted = 0;
        int verified = 0;

        for (OperationRecord r : allRecords) {
            if (r.isSuccess()) {
                if (r.getOperationType() == OperationRecord.OperationType.DOCUMENT_SCAN) {
                    scanned++;
                } else if (r.getOperationType() == OperationRecord.OperationType.DOCUMENT_REDACT) {
                    redacted++;
                } else if (r.getOperationType() == OperationRecord.OperationType.SIGNATURE_VERIFY) {
                    verified++;
                }
            }
        }

        scannedCountLabel.setText(String.valueOf(scanned));
        redactedCountLabel.setText(String.valueOf(redacted));
        verifiedCountLabel.setText(String.valueOf(verified));

        String selectedAlias = context.getActiveKeyAlias();
        if (selectedAlias != null) {
            keyStatusLabel.setText(selectedAlias);
        } else {
            keyStatusLabel.setText("Not Configured");
        }

        // Populate recent activity
        activityModel.setRowCount(0);
        int limit = Math.min(allRecords.size(), 8);

        if (allRecords.isEmpty()) {
            tableScrollPane.setViewportView(emptyStatePanel);
        } else {
            tableScrollPane.setViewportView(recentActivityTable);
            for (int i = 0; i < limit; i++) {
                OperationRecord r = allRecords.get(i);
                activityModel.addRow(new Object[]{
                        TIME_FORMATTER.format(r.getTimestamp()),
                        r.getOperationType().name(),
                        r.getDocumentIdentifier(),
                        r.isSuccess() ? "SUCCESS" : "FAILED",
                        r.getDetails()
                });
            }
        }
    }
}
