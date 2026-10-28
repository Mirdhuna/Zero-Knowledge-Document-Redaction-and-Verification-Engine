package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.model.KeyInfo;
import com.zeroknowledge.model.OperationRecord;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Dashboard screen providing an overview of recent operations, security metrics,
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
                "Detect and mask sensitive PII/secrets, compute verifiable SHA-256 digests, and validate detached RSA signatures."
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
        topContainer.add(Box.createVerticalStrut(16));

        // Metric Counter Cards (4 columns)
        JPanel statsGrid = new JPanel(new GridLayout(1, 4, 16, 0));
        statsGrid.setOpaque(false);

        scannedCountLabel = new JLabel("0");
        redactedCountLabel = new JLabel("0");
        verifiedCountLabel = new JLabel("0");
        keyStatusLabel = new JLabel("None");

        statsGrid.add(createMetricCard("Scanned Documents", scannedCountLabel, "Locally processed", ThemeManager.PRIMARY_BLUE));
        statsGrid.add(createMetricCard("Redacted Documents", redactedCountLabel, "Sanitized & saved", ThemeManager.SUCCESS_GREEN));
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
        String[] columns = {"Timestamp", "Operation", "Document", "Status", "Details"};
        activityModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        recentActivityTable = new JTable(activityModel);
        ThemeManager.styleTable(recentActivityTable);
        recentActivityTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        recentActivityTable.getColumnModel().getColumn(1).setPreferredWidth(90);
        recentActivityTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        recentActivityTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        recentActivityTable.getColumnModel().getColumn(4).setPreferredWidth(220);

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

        rightInfoCard.add(createSecurityBullet("Pure In-Memory Redaction",
                "Matches are redacted directly via memory streams. Original files are never modified without explicit approval."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Deterministic SHA-256",
                "Cryptographic hashes are calculated directly using JDK standard MessageDigest before and after redaction."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Asymmetric Detached Signatures",
                "Documents can be signed using RSA private keys. Detached signatures allow third-party verification without exposing original contents."));
        rightInfoCard.add(Box.createVerticalStrut(10));

        rightInfoCard.add(createSecurityBullet("Honest Verification Assurance",
                "Verification checks cryptographic consistency relative to a public key. It does not make false zero-knowledge claims."));

        centerContainer.add(rightInfoCard, BorderLayout.EAST);
        add(centerContainer, BorderLayout.CENTER);
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
     * Refreshes dashboard statistics and recent activity table from real backend data.
     */
    public void refreshData() {
        int scanned = context.getAuditService().getScannedCount();
        int redacted = context.getAuditService().getRedactedCount();
        int verified = context.getAuditService().getVerifiedCount();

        scannedCountLabel.setText(String.valueOf(scanned));
        redactedCountLabel.setText(String.valueOf(redacted));
        verifiedCountLabel.setText(String.valueOf(verified));

        String selectedAlias = context.getCryptoService().getSelectedAlias();
        if (selectedAlias != null) {
            KeyInfo info = context.getCryptoService().getKeyInfo(selectedAlias);
            if (info != null) {
                keyStatusLabel.setText(info.getAlgorithm() + " " + info.getKeySizeBits() + "b");
            } else {
                keyStatusLabel.setText(selectedAlias);
            }
        } else {
            keyStatusLabel.setText("Not Configured");
        }

        // Populate recent activity
        activityModel.setRowCount(0);
        List<OperationRecord> records = context.getAuditService().getRecords();

        if (records.isEmpty()) {
            tableScrollPane.setViewportView(emptyStatePanel);
        } else {
            tableScrollPane.setViewportView(recentActivityTable);
            int limit = Math.min(records.size(), 8);
            for (int i = 0; i < limit; i++) {
                OperationRecord r = records.get(i);
                activityModel.addRow(new Object[]{
                        r.getFormattedTimestamp(),
                        r.getOperationType().name(),
                        r.getDocumentIdentifier(),
                        r.getStatus().name(),
                        r.getDetails()
                });
            }
        }
    }
}
