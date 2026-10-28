package com.zeroknowledge.frontend;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.backend.RedactionService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Settings and Documentation Workspace:
 * Manages operational configurations (output dirs, detection patterns)
 * and provides educational documentation on cryptographic definitions.
 */
public class SettingsPanel extends JPanel {

    private final BackendContext context;
    private final Consumer<String> navigationConsumer;

    private JTextField outputDirField;
    private JTextField keyDirField;
    private final Map<String, JCheckBox> patternCheckBoxes = new HashMap<>();

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

        // Settings Form Card
        contentContainer.add(createConfigurationCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Detection Rules Card
        contentContainer.add(createDetectionRulesCard());
        contentContainer.add(Box.createVerticalStrut(16));

        // Security Education & Concepts Card
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

        JLabel desc = new JLabel("Configure engine parameters, default file destinations, and review cryptographic definitions.");
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

    private JPanel createConfigurationCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 14));

        JLabel title = new JLabel("Storage & Path Configurations");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 4, 6, 4);

        // Output Dir
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel outLbl = new JLabel("Default Output Directory:");
        outLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(outLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        outputDirField = new JTextField(context.getConfigService().getOutputDirectory());
        outputDirField.setFont(ThemeManager.FONT_REGULAR);
        form.add(outputDirField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JButton browseOutBtn = ThemeManager.createSecondaryButton("Browse...");
        browseOutBtn.addActionListener(e -> {
            JFileChooser ch = new JFileChooser();
            ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                outputDirField.setText(ch.getSelectedFile().getAbsolutePath());
            }
        });
        form.add(browseOutBtn, gbc);

        // Key Dir
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        JLabel keyLbl = new JLabel("Key Storage Directory:");
        keyLbl.setFont(ThemeManager.FONT_SMALL_BOLD);
        form.add(keyLbl, gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        keyDirField = new JTextField(context.getConfigService().getKeysDirectory());
        keyDirField.setFont(ThemeManager.FONT_REGULAR);
        form.add(keyDirField, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.0;
        JButton browseKeyBtn = ThemeManager.createSecondaryButton("Browse...");
        browseKeyBtn.addActionListener(e -> {
            JFileChooser ch = new JFileChooser();
            ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                keyDirField.setText(ch.getSelectedFile().getAbsolutePath());
            }
        });
        form.add(browseKeyBtn, gbc);

        card.add(form, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnRow.setOpaque(false);
        JButton saveBtn = ThemeManager.createPrimaryButton("Save Paths");
        saveBtn.addActionListener(e -> {
            context.getConfigService().setOutputDirectory(outputDirField.getText().trim());
            context.getConfigService().setKeysDirectory(keyDirField.getText().trim());
            DialogManager.showInfo(this, "Settings Saved", "Path configurations updated successfully.");
        });
        btnRow.add(saveBtn);
        card.add(btnRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createDetectionRulesCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Detection Pattern Rules");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        JPanel checkGrid = new JPanel(new GridLayout(3, 2, 12, 8));
        checkGrid.setOpaque(false);

        for (RedactionService.PatternRule rule : context.getRedactionService().getRules()) {
            boolean enabled = context.getConfigService().isPatternEnabled(rule.getType());
            JCheckBox cb = new JCheckBox(rule.getType() + " - " + rule.getDescription(), enabled);
            cb.setFont(ThemeManager.FONT_SMALL);
            cb.setOpaque(false);
            cb.addActionListener(e -> {
                context.getConfigService().setPatternEnabled(rule.getType(), cb.isSelected());
            });
            patternCheckBoxes.put(rule.getType(), cb);
            checkGrid.add(cb);
        }

        card.add(checkGrid, BorderLayout.CENTER);
        return card;
    }

    private JPanel createEducationalCard() {
        JPanel card = ThemeManager.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Security & Cryptographic Foundations");
        title.setFont(ThemeManager.FONT_HEADER);
        title.setForeground(ThemeManager.TEXT_PRIMARY);
        card.add(title);
        card.add(Box.createVerticalStrut(12));

        card.add(createConceptBlock(
                "1. Document Redaction",
                "Irreversible sanitization of identified sensitive character spans from a document stream prior to export. True redaction removes underlying bytes completely, unlike visual masking in PDFs which often leaves raw text extractable."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "2. Cryptographic Hashing (SHA-256)",
                "A one-way deterministic mathematical function that produces a unique 256-bit digest for any given file. Any modification to a document, even a single bit, alters the resulting hash completely."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "3. Asymmetric Digital Signatures (RSA)",
                "Signing uses a private key known only to the signer to encrypt the SHA-256 hash of a file. Anyone with the matching public key can decrypt the signature and confirm that the document has not been altered since signing."
        ));
        card.add(Box.createVerticalStrut(10));

        card.add(createConceptBlock(
                "4. Honest Disclosure: Zero-Knowledge Distinction",
                "SHA-256 digests and RSA digital signatures alone do NOT constitute a Zero-Knowledge Proof (ZKP). A true ZKP mathematically proves a specific computational assertion (e.g. zk-SNARK) without revealing the underlying data. In this engine, redaction ensures data privacy while detached RSA signatures prove document integrity and authenticity."
        ));

        return card;
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
