package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.AccessControlService;
import com.zeroknowledge.storage.ApplicationConfig;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Settings and Documentation Workspace:
 * Displays engine operational parameters, active RBAC role selection,
 * and provides educational documentation on cryptographic definitions.
 */
public class SettingsPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JComboBox<AccessControlService.Role> roleComboBox;

    public SettingsPanel(BackendContext context, Consumer<String> navigationConsumer) {
        this.context = context;
        this.navigationConsumer = navigationConsumer;

        setLayout(new BorderLayout(0, 16));
        setBackground(ThemeManager.WORKSPACE_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        JPanel contentContainer = new JPanel();
        contentContainer.setLayout(new BoxLayout(contentContainer, BoxLayout.Y_AXIS));
        contentContainer.setOpaque(false);

        // Header
        contentContainer.add(createHeaderPanel());
        contentContainer.add(Box.createVerticalStrut(16));

        // Engine Configuration Card
        contentContainer.add(createConfigCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Access Control Card
        contentContainer.add(createRbacCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Detection Rules Card
        contentContainer.add(createRulesCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Cryptographic Education Card
        contentContainer.add(createEducationalCard());

        JScrollPane scroll = new JScrollPane(contentContainer);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.getVerticalScrollBar().setUnitIncrement(16);

        add(scroll, BorderLayout.CENTER);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel title = new JLabel("Settings & Security Reference");
        title.setFont(ThemeManager.FONT_TITLE);
        title.setForeground(ThemeManager.TEXT_PRIMARY);

        JLabel desc = new JLabel("Review engine parameters, manage RBAC permissions, and review cryptographic definitions.");
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

    private JPanel createConfigCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Backend Application Configuration");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        ApplicationConfig cfg = context.getApplicationConfig();

        JPanel grid = new JPanel(new GridLayout(3, 2, 16, 8));
        grid.setOpaque(false);

        grid.add(createConfigItem("Working Directory", cfg.getWorkingDirectory().toAbsolutePath().toString()));
        grid.add(createConfigItem("Key Store Directory", cfg.getKeyStoreDirectory().toAbsolutePath().toString()));
        grid.add(createConfigItem("Audit Log Path", cfg.getAuditLogPath().toAbsolutePath().toString()));
        grid.add(createConfigItem("Default Key Size", cfg.getDefaultRsaKeySizeBits() + " bits (RSA)"));
        grid.add(createConfigItem("Max Document Size", (cfg.getMaxDocumentSizeBytes() / (1024 * 1024)) + " MB"));
        grid.add(createConfigItem("Detached Signature Version", "ZK-SIG-1.0"));

        card.add(grid, BorderLayout.CENTER);
        return card;
    }

    private JPanel createRbacCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Role-Based Access Control (RBAC)");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 0));
        row.setOpaque(false);

        JLabel lbl = new JLabel("Active Security Role:");
        lbl.setFont(ThemeManager.FONT_SMALL_BOLD);

        roleComboBox = new JComboBox<>(AccessControlService.Role.values());
        roleComboBox.setSelectedItem(context.getAccessControlService().getActiveRole());
        roleComboBox.setFont(ThemeManager.FONT_SMALL);
        roleComboBox.addActionListener(e -> {
            AccessControlService.Role r = (AccessControlService.Role) roleComboBox.getSelectedItem();
            if (r != null) {
                context.getAccessControlService().setActiveRole(r);
                DialogManager.showInfo(this, "Role Updated", "Active security role updated to: " + r.name());
            }
        });

        JLabel note = new JLabel("<html><span style='color: #64748B;'>Controls permission to generate keys, sign, and redact documents.</span></html>");
        note.setFont(ThemeManager.FONT_SMALL);

        row.add(lbl);
        row.add(roleComboBox);
        row.add(note);

        card.add(row, BorderLayout.CENTER);
        return card;
    }

    private JPanel createRulesCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Registered Sensitive-Data Detection Rules");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        JPanel rulesPanel = new JPanel();
        rulesPanel.setLayout(new BoxLayout(rulesPanel, BoxLayout.Y_AXIS));
        rulesPanel.setOpaque(false);

        List<com.zeroknowledge.backend.SensitiveDataDetector.DetectionRule> rules =
                context.getDocumentService().getSensitiveDataDetector().getRules();

        for (com.zeroknowledge.backend.SensitiveDataDetector.DetectionRule r : rules) {
            JPanel p = new JPanel(new BorderLayout(10, 0));
            p.setOpaque(false);
            p.setBorder(new EmptyBorder(3, 4, 3, 4));

            JLabel typeLbl = new JLabel("● " + r.getCandidateType() + " (" + r.getRuleId() + ")");
            typeLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
            typeLbl.setForeground(ThemeManager.TEXT_PRIMARY);

            JLabel confLbl = new JLabel("Confidence: " + (int)(r.getConfidence() * 100) + "%  |  Token: " + r.getReplacementToken());
            confLbl.setFont(ThemeManager.FONT_SMALL);
            confLbl.setForeground(ThemeManager.TEXT_SECONDARY);

            p.add(typeLbl, BorderLayout.WEST);
            p.add(confLbl, BorderLayout.EAST);
            rulesPanel.add(p);
        }

        card.add(rulesPanel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createEducationalCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Cryptographic Security Foundations");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title);
        card.add(Box.createVerticalStrut(12));

        card.add(createConceptBlock(
                "1. Document Redaction",
                "Irreversible sanitization of identified sensitive character spans prior to document export. Underlying text bytes are completely replaced with replacement tokens. Visual overlays in PDFs are rejected by design because they leave underlying content extractable."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "2. Streaming Cryptographic Hashing (SHA-256)",
                "A one-way deterministic mathematical function that produces a 256-bit digest over the exact byte stream of a file. Any bit modification results in a completely different digest."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "3. Detached Digital Signatures (SHA256withRSA)",
                "Signing computes a digital signature over the exact document bytes using a private key. The resulting .zksig file is stored alongside the document, allowing verification against a trusted public key without modifying the source."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "4. Honest Disclosure: Zero-Knowledge Distinction",
                "SHA-256 digests and RSA digital signatures alone do NOT constitute a Zero-Knowledge Proof (ZKP). A true ZKP mathematically proves a specific computational assertion (e.g. zk-SNARK) without revealing underlying inputs. In this engine, redaction ensures data privacy while detached RSA signatures prove document integrity and authenticity."
        ));

        return card;
    }

    private JPanel createConfigItem(String key, String value) {
        JPanel p = new JPanel(new BorderLayout(0, 2));
        p.setOpaque(false);

        JLabel k = new JLabel(key);
        k.setFont(ThemeManager.FONT_SMALL_BOLD);
        k.setForeground(ThemeManager.TEXT_SECONDARY);

        JLabel v = new JLabel(value);
        v.setFont(ThemeManager.FONT_SMALL);
        v.setForeground(ThemeManager.TEXT_PRIMARY);

        p.add(k, BorderLayout.NORTH);
        p.add(v, BorderLayout.CENTER);
        return p;
    }

    private JPanel createConceptBlock(String title, String explanation) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);

        JLabel t = new JLabel(title);
        t.setFont(ThemeManager.FONT_SUBHEADER);
        t.setForeground(ThemeManager.PRIMARY_BLUE);

        JLabel e = new JLabel("<html><body style='width: 600px; font-size: 10pt; color: #334155; line-height: 1.4;'>"
                + explanation + "</body></html>");
        e.setFont(ThemeManager.FONT_REGULAR);
        e.setBorder(new EmptyBorder(2, 6, 0, 0));

        p.add(t);
        p.add(e);
        return p;
    }
}
