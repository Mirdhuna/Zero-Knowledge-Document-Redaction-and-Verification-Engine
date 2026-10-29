package com.zeroknowledge.frontend;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;

/**
 * Main application window for the Zero-Knowledge Document Redaction & Verification Engine.
 * Manages global navigation, CardLayout screen switching, and application life cycle.
 */
public class MainFrame extends JFrame {

    public static final String CARD_DASHBOARD = "DASHBOARD";
    public static final String CARD_REDACTION = "REDACTION";
    public static final String CARD_VERIFICATION = "VERIFICATION";
    public static final String CARD_KEYS = "KEYS";
    public static final String CARD_AUDIT = "AUDIT";
    public static final String CARD_SETTINGS = "SETTINGS";

    private final BackendContext backendContext;
    private final CardLayout cardLayout;
    private final JPanel contentCardPanel;

    // Workspace panels
    private final DashboardPanel dashboardPanel;
    private final RedactionPanel redactionPanel;
    private final VerificationPanel verificationPanel;
    private final KeyManagementPanel keyManagementPanel;
    private final AuditPanel auditPanel;
    private final SettingsPanel settingsPanel;

    // Navigation UI
    private final Map<String, JButton> navButtons = new HashMap<>();
    private JLabel currentSectionTitleLabel;
    private JLabel currentSectionBreadcrumbLabel;
    private JLabel statusBarLabel;
    private String currentCard = CARD_DASHBOARD;

    public MainFrame() {
        this(new BackendContext());
    }

    public MainFrame(BackendContext context) {
        super("Zero-Knowledge Document Redaction & Verification Engine");
        this.backendContext = context;

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1140, 780);
        setMinimumSize(new Dimension(960, 640));
        setLocationRelativeTo(null);

        // Application Icon
        Image appIcon = createAppIcon();
        if (appIcon != null) {
            setIconImage(appIcon);
        }

        // Layout setup
        cardLayout = new CardLayout();
        contentCardPanel = new JPanel(cardLayout);
        contentCardPanel.setBackground(ThemeManager.WORKSPACE_BG);

        // Initialize Workspace Panels
        dashboardPanel = new DashboardPanel(backendContext, this::navigateTo);
        redactionPanel = new RedactionPanel(backendContext, this::navigateTo);
        verificationPanel = new VerificationPanel(backendContext, this::navigateTo);
        keyManagementPanel = new KeyManagementPanel(backendContext, this::navigateTo);
        auditPanel = new AuditPanel(backendContext, this::navigateTo);
        settingsPanel = new SettingsPanel(backendContext, this::navigateTo);

        contentCardPanel.add(dashboardPanel, CARD_DASHBOARD);
        contentCardPanel.add(redactionPanel, CARD_REDACTION);
        contentCardPanel.add(verificationPanel, CARD_VERIFICATION);
        contentCardPanel.add(keyManagementPanel, CARD_KEYS);
        contentCardPanel.add(auditPanel, CARD_AUDIT);
        contentCardPanel.add(settingsPanel, CARD_SETTINGS);

        // Root Window Structure
        JPanel rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(ThemeManager.WORKSPACE_BG);

        // Sidebar Navigation
        JPanel sidebar = createSidebar();
        rootPanel.add(sidebar, BorderLayout.WEST);

        // Main Center Area (Top App Bar + Content Card Panel + Status Bar)
        JPanel mainArea = new JPanel(new BorderLayout());
        mainArea.setBackground(ThemeManager.WORKSPACE_BG);

        mainArea.add(createTopBar(), BorderLayout.NORTH);
        mainArea.add(contentCardPanel, BorderLayout.CENTER);
        mainArea.add(createStatusBar(), BorderLayout.SOUTH);

        rootPanel.add(mainArea, BorderLayout.CENTER);
        setContentPane(rootPanel);

        // Default screen
        navigateTo(CARD_DASHBOARD);
    }

    private JPanel createSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(240, 0));
        sidebar.setBackground(ThemeManager.SIDEBAR_BG);
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(30, 41, 59)));

        // Branding Header
        JPanel brandPanel = new JPanel();
        brandPanel.setLayout(new BoxLayout(brandPanel, BoxLayout.Y_AXIS));
        brandPanel.setOpaque(false);
        brandPanel.setBorder(new EmptyBorder(22, 20, 22, 20));

        JLabel brandTitle = new JLabel("ZK ENGINE");
        brandTitle.setFont(new Font("SansSerif", Font.BOLD, 17));
        brandTitle.setForeground(Color.WHITE);

        JLabel brandSub = new JLabel("Redaction & Verification");
        brandSub.setFont(new Font("SansSerif", Font.PLAIN, 12));
        brandSub.setForeground(ThemeManager.SIDEBAR_TEXT_MUTED);

        brandPanel.add(brandTitle);
        brandPanel.add(Box.createVerticalStrut(2));
        brandPanel.add(brandSub);
        sidebar.add(brandPanel, BorderLayout.NORTH);

        // Navigation Buttons List
        JPanel navList = new JPanel();
        navList.setLayout(new BoxLayout(navList, BoxLayout.Y_AXIS));
        navList.setOpaque(false);
        navList.setBorder(new EmptyBorder(10, 12, 10, 12));

        addNavButton(navList, "Dashboard", CARD_DASHBOARD, "System metrics & quick actions");
        navList.add(Box.createVerticalStrut(6));
        addNavButton(navList, "Redact Document", CARD_REDACTION, "Scan & mask sensitive entities");
        navList.add(Box.createVerticalStrut(6));
        addNavButton(navList, "Verify Document", CARD_VERIFICATION, "Verify cryptographic signatures");
        navList.add(Box.createVerticalStrut(6));
        addNavButton(navList, "Key Management", CARD_KEYS, "RSA key generation & export");
        navList.add(Box.createVerticalStrut(6));
        addNavButton(navList, "Audit & Activity", CARD_AUDIT, "Immutable local audit records");
        navList.add(Box.createVerticalStrut(6));
        addNavButton(navList, "Settings & Help", CARD_SETTINGS, "Configuration & security guide");

        sidebar.add(navList, BorderLayout.CENTER);

        // Sidebar Footer Status
        JPanel sidebarFooter = new JPanel(new BorderLayout());
        sidebarFooter.setOpaque(false);
        sidebarFooter.setBorder(new EmptyBorder(16, 20, 16, 20));

        JLabel envLabel = new JLabel("Java 21 • Standard JDK");
        envLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        envLabel.setForeground(ThemeManager.SIDEBAR_TEXT_MUTED);

        sidebarFooter.add(envLabel, BorderLayout.WEST);
        sidebar.add(sidebarFooter, BorderLayout.SOUTH);

        return sidebar;
    }

    private void addNavButton(JPanel container, String text, String cardKey, String tooltip) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                boolean isActive = cardKey.equals(currentCard);
                if (isActive) {
                    g2.setColor(ThemeManager.SIDEBAR_ACTIVE);
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                    g2.setColor(ThemeManager.PRIMARY_BLUE);
                    g2.fillRoundRect(0, 4, 4, getHeight() - 8, 2, 2);
                } else if (getModel().isRollover()) {
                    g2.setColor(ThemeManager.SIDEBAR_HOVER);
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                }

                g2.dispose();
                super.paintComponent(g);
            }
        };

        btn.setFont(ThemeManager.FONT_REGULAR_BOLD);
        btn.setForeground(ThemeManager.SIDEBAR_TEXT);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(10, 16, 10, 16));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        btn.setToolTipText(tooltip);

        btn.addActionListener(e -> navigateTo(cardKey));

        navButtons.put(cardKey, btn);
        container.add(btn);
    }

    private JPanel createTopBar() {
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setBackground(Color.WHITE);
        topBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, ThemeManager.CARD_BORDER));
        topBar.setPreferredSize(new Dimension(0, 56));
        topBar.setBorder(new EmptyBorder(0, 24, 0, 24));

        JPanel titleBox = new JPanel();
        titleBox.setLayout(new BoxLayout(titleBox, BoxLayout.Y_AXIS));
        titleBox.setOpaque(false);

        currentSectionBreadcrumbLabel = new JLabel("Engine / Workspace");
        currentSectionBreadcrumbLabel.setFont(ThemeManager.FONT_SMALL);
        currentSectionBreadcrumbLabel.setForeground(ThemeManager.TEXT_MUTED);

        currentSectionTitleLabel = new JLabel("Dashboard");
        currentSectionTitleLabel.setFont(ThemeManager.FONT_HEADER);
        currentSectionTitleLabel.setForeground(ThemeManager.TEXT_PRIMARY);

        titleBox.add(Box.createVerticalStrut(8));
        titleBox.add(currentSectionBreadcrumbLabel);
        titleBox.add(currentSectionTitleLabel);
        topBar.add(titleBox, BorderLayout.WEST);

        JPanel rightInfo = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 14));
        rightInfo.setOpaque(false);

        JLabel statusDot = new JLabel("● Backend Engine Operational");
        statusDot.setFont(ThemeManager.FONT_SMALL_BOLD);
        statusDot.setForeground(ThemeManager.SUCCESS_GREEN);
        rightInfo.add(statusDot);

        topBar.add(rightInfo, BorderLayout.EAST);
        return topBar;
    }

    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBackground(Color.WHITE);
        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, ThemeManager.CARD_BORDER));
        statusBar.setPreferredSize(new Dimension(0, 28));
        statusBar.setBorder(new EmptyBorder(4, 24, 4, 24));

        statusBarLabel = new JLabel("Zero-Knowledge Document Redaction & Verification Engine • System Operational");
        statusBarLabel.setFont(ThemeManager.FONT_SMALL);
        statusBarLabel.setForeground(ThemeManager.TEXT_MUTED);

        JLabel sessionInfo = new JLabel("Session Memory KeyStore Active");
        sessionInfo.setFont(ThemeManager.FONT_SMALL);
        sessionInfo.setForeground(ThemeManager.TEXT_MUTED);

        statusBar.add(statusBarLabel, BorderLayout.WEST);
        statusBar.add(sessionInfo, BorderLayout.EAST);
        return statusBar;
    }

    public void navigateTo(String cardKey) {
        this.currentCard = cardKey;
        cardLayout.show(contentCardPanel, cardKey);

        for (Map.Entry<String, JButton> entry : navButtons.entrySet()) {
            boolean active = entry.getKey().equals(cardKey);
            JButton b = entry.getValue();
            b.setForeground(active ? Color.WHITE : ThemeManager.SIDEBAR_TEXT);
            b.repaint();
        }

        switch (cardKey) {
            case CARD_DASHBOARD:
                currentSectionBreadcrumbLabel.setText("Engine / Overview");
                currentSectionTitleLabel.setText("Dashboard");
                dashboardPanel.refreshData();
                setStatusBarMessage("Dashboard loaded with real local metrics.");
                break;
            case CARD_REDACTION:
                currentSectionBreadcrumbLabel.setText("Workspaces / Sanitization");
                currentSectionTitleLabel.setText("Document Redaction");
                redactionPanel.refreshKeySelector();
                setStatusBarMessage("Redaction workspace active. Select document to scan.");
                break;
            case CARD_VERIFICATION:
                currentSectionBreadcrumbLabel.setText("Workspaces / Cryptography");
                currentSectionTitleLabel.setText("Signature Verification");
                verificationPanel.refreshKeySources();
                setStatusBarMessage("Verification workspace active. Select document and signature.");
                break;
            case CARD_KEYS:
                currentSectionBreadcrumbLabel.setText("Security / Identities");
                currentSectionTitleLabel.setText("Key Management");
                keyManagementPanel.refreshKeyTable();
                setStatusBarMessage("Key management active. RSA 2048/3072/4096-bit supported.");
                break;
            case CARD_AUDIT:
                currentSectionBreadcrumbLabel.setText("Compliance / Logs");
                currentSectionTitleLabel.setText("Audit & Activity Log");
                auditPanel.refreshAuditTable();
                setStatusBarMessage("Audit log records retrieved from local log file.");
                break;
            case CARD_SETTINGS:
                currentSectionBreadcrumbLabel.setText("System / Preferences");
                currentSectionTitleLabel.setText("Settings & Security Reference");
                setStatusBarMessage("Engine settings and cryptographic documentation.");
                break;
        }
    }

    public void setStatusBarMessage(String message) {
        if (statusBarLabel != null) {
            statusBarLabel.setText(message);
        }
    }

    private Image createAppIcon() {
        int size = 64;
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        g2.setColor(ThemeManager.PRIMARY_BLUE);
        g2.fillRoundRect(4, 4, size - 8, size - 8, 16, 16);

        g2.setColor(Color.WHITE);
        g2.setStroke(new BasicStroke(3.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

        g2.drawArc(22, 16, 20, 20, 0, 180);
        g2.fillRoundRect(18, 26, 28, 22, 6, 6);
        g2.setColor(ThemeManager.PRIMARY_BLUE);
        g2.fillOval(30, 32, 4, 4);
        g2.fillRect(31, 34, 2, 6);

        g2.dispose();
        return img;
    }

    public static void main(String[] args) {
        ThemeManager.setupLookAndFeel();

        SwingUtilities.invokeLater(() -> {
            MainFrame frame = new MainFrame();
            frame.setVisible(true);
        });
    }
}
