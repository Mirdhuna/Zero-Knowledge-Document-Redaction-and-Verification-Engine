package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.AccessControlService;
import com.zeroknowledge.document.OcrEngine.OcrAvailability;
import com.zeroknowledge.document.TesseractOcrEngine;
import com.zeroknowledge.storage.ApplicationConfig;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.function.Consumer;

/**
 * Settings and Documentation Workspace:
 * Displays engine operational parameters, local Tesseract OCR configuration,
 * active RBAC role selection, and educational documentation on cryptographic definitions.
 */
public class SettingsPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JComboBox<AccessControlService.Role> roleComboBox;
    private JTextField tesseractPathField;
    private JTextField tessdataDirField;
    private JTextField ocrLangField;
    private JTextField ocrDpiField;
    private JLabel ocrStatusTestLabel;

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

        // Local OCR Configuration Card
        contentContainer.add(createOcrConfigCard());
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

        JLabel desc = new JLabel("Configure local Tesseract OCR parameters, manage RBAC permissions, and review detection & cryptographic rules.");
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

    private JPanel createOcrConfigCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Local Tesseract OCR Configuration (Zero External Uploads)");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        ApplicationConfig cfg = context.getApplicationConfig();

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 6, 6, 6);

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        form.add(new JLabel("Tesseract Executable:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        tesseractPathField = ThemeManager.createTextField();
        tesseractPathField.setText(cfg.getTesseractExecutablePath());
        form.add(tesseractPathField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        form.add(new JLabel("Tessdata Directory (Optional):"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        tessdataDirField = ThemeManager.createTextField();
        tessdataDirField.setText(cfg.getTessdataDirectory() != null ? cfg.getTessdataDirectory().toString() : "");
        form.add(tessdataDirField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0;
        form.add(new JLabel("OCR Language Code (e.g. eng):"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        ocrLangField = ThemeManager.createTextField();
        ocrLangField.setText(cfg.getOcrLanguage());
        form.add(ocrLangField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0;
        form.add(new JLabel("Scan Render Resolution (DPI):"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0;
        ocrDpiField = ThemeManager.createTextField();
        ocrDpiField.setText(String.valueOf(cfg.getOcrRenderDpi()));
        form.add(ocrDpiField, gbc);

        ocrStatusTestLabel = new JLabel("Click 'Apply & Test OCR' to verify local Tesseract installation.");
        ocrStatusTestLabel.setFont(ThemeManager.FONT_SMALL);
        ocrStatusTestLabel.setForeground(ThemeManager.TEXT_SECONDARY);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);

        JButton setupGuideBtn = ThemeManager.createSecondaryButton("Setup Instructions");
        setupGuideBtn.addActionListener(e -> {
            String instructions = TesseractOcrEngine.SETUP_INSTRUCTIONS;
            JTextArea area = new JTextArea(instructions, 16, 60);
            area.setEditable(false);
            area.setFont(ThemeManager.FONT_MONO);
            JOptionPane.showMessageDialog(this, new JScrollPane(area), "Local Tesseract OCR Setup", JOptionPane.INFORMATION_MESSAGE);
        });

        JButton applyOcrBtn = ThemeManager.createPrimaryButton("Apply & Test OCR Engine");
        applyOcrBtn.addActionListener(e -> handleApplyAndTestOcr());

        btnRow.add(setupGuideBtn);
        btnRow.add(applyOcrBtn);

        JPanel southPanel = new JPanel(new BorderLayout(8, 6));
        southPanel.setOpaque(false);
        southPanel.add(ocrStatusTestLabel, BorderLayout.WEST);
        southPanel.add(btnRow, BorderLayout.EAST);

        card.add(form, BorderLayout.CENTER);
        card.add(southPanel, BorderLayout.SOUTH);
        return card;
    }

    private void handleApplyAndTestOcr() {
        try {
            String exec = tesseractPathField.getText().trim();
            String tessDirStr = tessdataDirField.getText().trim();
            Path tessDir = tessDirStr.isEmpty() ? null : Paths.get(tessDirStr);
            String lang = ocrLangField.getText().trim().isEmpty() ? "eng" : ocrLangField.getText().trim();
            int dpi = Integer.parseInt(ocrDpiField.getText().trim());

            context.updateOcrSettings(exec, tessDir, lang, dpi, context.getApplicationConfig().getMinOcrConfidence());
            TesseractOcrEngine engine = new TesseractOcrEngine(context.getApplicationConfig());
            OcrAvailability avail = engine.checkAvailability();

            if (avail.isAvailable()) {
                ocrStatusTestLabel.setText("✓ " + avail.getStatusMessage());
                ocrStatusTestLabel.setForeground(ThemeManager.SUCCESS_GREEN);
                DialogManager.showInfo(this, "OCR Engine Ready", avail.getStatusMessage());
            } else {
                ocrStatusTestLabel.setText("⚠ " + avail.getStatusMessage());
                ocrStatusTestLabel.setForeground(ThemeManager.WARNING_AMBER);
                DialogManager.showWarning(this, "OCR Unavailable",
                        avail.getStatusMessage() + "<br><br>Click <b>Setup Instructions</b> for installation details.");
            }
        } catch (Exception ex) {
            DialogManager.showError(this, "Invalid OCR Configuration", "Please check OCR settings: " + ex.getMessage());
        }
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

        roleComboBox = ThemeManager.createComboBox();
        for (AccessControlService.Role r : AccessControlService.Role.values()) {
            roleComboBox.addItem(r);
        }
        roleComboBox.setSelectedItem(context.getAccessControlService().getActiveRole());
        roleComboBox.addActionListener(e -> {
            AccessControlService.Role r = (AccessControlService.Role) roleComboBox.getSelectedItem();
            if (r != null) {
                context.getAccessControlService().setActiveRole(r);
                DialogManager.showInfo(this, "Role Updated", "Active security role updated to: " + r.name());
            }
        });

        JLabel note = new JLabel("<html><span style='color: #475569;'>Controls permission to generate keys, sign, and redact documents.</span></html>");
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

        JLabel title = new JLabel("Registered Context-Aware Sensitive-Data Detection Rules");
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
            p.setBorder(new EmptyBorder(4, 6, 4, 6));

            JLabel typeLbl = new JLabel("● " + r.getCandidateType() + " (" + r.getRuleId() + ")");
            typeLbl.setFont(ThemeManager.FONT_REGULAR_BOLD);
            typeLbl.setForeground(ThemeManager.TEXT_PRIMARY);

            JLabel confLbl = new JLabel("Confidence: " + (int) (r.getConfidence() * 100) + "%  |  Token: " + r.getReplacementToken());
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

        JLabel title = new JLabel("Cryptographic & Redaction Security Foundations");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title);
        card.add(Box.createVerticalStrut(14));

        card.add(createConceptBlock(
                "1. Permanent Native & Image PDF Redaction",
                "For native PDF text, sensitive characters are physically excised from decompressed Tj/TJ content streams (replacing deleted glyph widths with negative TJ kerning shifts so surrounding layout is preserved) and covered with opaque black rectangles. For scanned image pages, opaque black pixels are burned directly into the raster image and the PDF Image XObject stream is replaced so the original unredacted image is never retained."
        ));
        card.add(Box.createVerticalStrut(12));

        card.add(createConceptBlock(
                "2. Independent Post-Redaction Verification",
                "After saving a redacted PDF, the engine reopens the output file from disk, re-extracts all text streams, and inspects target image pixel regions to verify that redacted values are no longer extractable or visible. Automated checks substantially reduce risk but cannot mathematically prove the absence of every possible disclosure."
        ));
        card.add(Box.createVerticalStrut(12));

        card.add(createConceptBlock(
                "3. Streaming Cryptographic Hashing (SHA-256) & Detached Signatures (SHA256withRSA)",
                "Every redacted output file receives a fresh SHA-256 digest and a new detached .zksig RSA signature. Original document signatures are never reused for modified outputs."
        ));
        card.add(Box.createVerticalStrut(12));

        card.add(createConceptBlock(
                "4. Honest Disclosure: Zero-Knowledge Distinction",
                "SHA-256 digests and RSA digital signatures alone do NOT constitute a Zero-Knowledge Proof (ZKP). In this engine, permanent content excision ensures data privacy while detached RSA signatures prove document integrity and authenticity."
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
        v.setFont(ThemeManager.FONT_REGULAR);
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

        JLabel e = new JLabel("<html><body style='width: 640px; font-size: 11pt; color: #1E293B; line-height: 1.5;'>"
                + explanation + "</body></html>");
        e.setFont(ThemeManager.FONT_REGULAR);
        e.setBorder(new EmptyBorder(4, 6, 0, 0));

        p.add(t);
        p.add(e);
        return p;
    }
}
