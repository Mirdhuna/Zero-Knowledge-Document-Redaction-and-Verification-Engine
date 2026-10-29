package com.zeroknowledge.frontend;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * Centralized theme, high-contrast color palette, readable typography, and UI component styling.
 * Prevents Linux GTK dark-theme conflicts by guaranteeing explicit foreground and background pairs.
 */
public final class ThemeManager {

    private ThemeManager() {}

    // High-Contrast Color Palette
    public static final Color SIDEBAR_BG = new Color(15, 23, 42);           // #0F172A Deep Slate Navy
    public static final Color SIDEBAR_HOVER = new Color(30, 41, 59);        // #1E293B
    public static final Color SIDEBAR_ACTIVE = new Color(51, 65, 85);       // #334155
    public static final Color SIDEBAR_TEXT = new Color(248, 250, 252);      // #F8FAFC Crisp White
    public static final Color SIDEBAR_TEXT_MUTED = new Color(148, 163, 184);// #94A3B8

    public static final Color WORKSPACE_BG = new Color(241, 245, 249);     // #F1F5F9 Soft Slate
    public static final Color CARD_BG = new Color(255, 255, 255);          // Pure White
    public static final Color CARD_BORDER = new Color(203, 213, 225);      // #CBD5E1 Crisp Border

    public static final Color INPUT_BG = Color.WHITE;
    public static final Color INPUT_FG = new Color(15, 23, 42);
    public static final Color INPUT_BORDER = new Color(203, 213, 225);

    public static final Color PRIMARY_BLUE = new Color(2, 132, 199);       // #0284C7
    public static final Color PRIMARY_BLUE_HOVER = new Color(3, 105, 161); // #0369A1

    public static final Color SUCCESS_GREEN = new Color(22, 163, 74);      // Verified
    public static final Color SUCCESS_BG = new Color(240, 253, 244);
    public static final Color SUCCESS_BORDER = new Color(134, 239, 172);

    public static final Color WARNING_AMBER = new Color(217, 119, 6);      // Notice
    public static final Color WARNING_BG = new Color(254, 252, 232);
    public static final Color WARNING_BORDER = new Color(253, 224, 71);

    public static final Color DANGER_RED = new Color(220, 38, 38);         // Destructive / Mismatch
    public static final Color DANGER_BG = new Color(254, 242, 242);
    public static final Color DANGER_BORDER = new Color(252, 165, 165);

    public static final Color TEXT_PRIMARY = new Color(15, 23, 42);        // #0F172A Near Black / Slate
    public static final Color TEXT_SECONDARY = new Color(51, 65, 85);      // #334155
    public static final Color TEXT_MUTED = new Color(100, 116, 139);       // #64748B

    public static final Color TABLE_HEADER_BG = new Color(241, 245, 249);
    public static final Color TABLE_GRID = new Color(226, 232, 240);
    public static final Color TABLE_SELECTION = new Color(224, 242, 254);

    // Readable, Scaled Typography (14pt+ base)
    public static final Font FONT_TITLE = new Font("SansSerif", Font.BOLD, 24);
    public static final Font FONT_HEADER = new Font("SansSerif", Font.BOLD, 18);
    public static final Font FONT_SUBHEADER = new Font("SansSerif", Font.BOLD, 15);
    public static final Font FONT_REGULAR = new Font("SansSerif", Font.PLAIN, 14);
    public static final Font FONT_REGULAR_BOLD = new Font("SansSerif", Font.BOLD, 14);
    public static final Font FONT_SMALL = new Font("SansSerif", Font.PLAIN, 13);
    public static final Font FONT_SMALL_BOLD = new Font("SansSerif", Font.BOLD, 13);
    public static final Font FONT_MONO = new Font("Monospaced", Font.PLAIN, 13);
    public static final Font FONT_MONO_BOLD = new Font("Monospaced", Font.BOLD, 13);

    /**
     * Initializes global Swing LookAndFeel defaults with explicit high-contrast colors
     * to eliminate black-on-black or illegible native GTK dark-theme overrides on Linux.
     */
    public static void setupLookAndFeel() {
        try {
            // Use Metal CrossPlatform L&F with customized palette to prevent GTK dark collisions
            UIManager.setLookAndFeel(new MetalLookAndFeel());
        } catch (Exception ignored) {
        }

        // Global High-Contrast Color Defaults
        UIManager.put("Panel.background", WORKSPACE_BG);
        UIManager.put("Panel.foreground", TEXT_PRIMARY);
        UIManager.put("Label.font", FONT_REGULAR);
        UIManager.put("Label.foreground", TEXT_PRIMARY);

        UIManager.put("TextField.font", FONT_REGULAR);
        UIManager.put("TextField.background", Color.WHITE);
        UIManager.put("TextField.foreground", TEXT_PRIMARY);
        UIManager.put("TextField.caretForeground", TEXT_PRIMARY);
        UIManager.put("TextField.selectionBackground", TABLE_SELECTION);
        UIManager.put("TextField.selectionForeground", TEXT_PRIMARY);

        UIManager.put("TextArea.font", FONT_MONO);
        UIManager.put("TextArea.background", Color.WHITE);
        UIManager.put("TextArea.foreground", TEXT_PRIMARY);
        UIManager.put("TextArea.caretForeground", TEXT_PRIMARY);

        UIManager.put("ComboBox.font", FONT_REGULAR);
        UIManager.put("ComboBox.background", Color.WHITE);
        UIManager.put("ComboBox.foreground", TEXT_PRIMARY);
        UIManager.put("ComboBox.selectionBackground", PRIMARY_BLUE);
        UIManager.put("ComboBox.selectionForeground", Color.WHITE);

        UIManager.put("Table.font", FONT_REGULAR);
        UIManager.put("Table.background", Color.WHITE);
        UIManager.put("Table.foreground", TEXT_PRIMARY);
        UIManager.put("Table.gridColor", TABLE_GRID);
        UIManager.put("Table.selectionBackground", TABLE_SELECTION);
        UIManager.put("Table.selectionForeground", TEXT_PRIMARY);

        UIManager.put("TableHeader.font", FONT_SMALL_BOLD);
        UIManager.put("TableHeader.background", TABLE_HEADER_BG);
        UIManager.put("TableHeader.foreground", TEXT_PRIMARY);

        UIManager.put("ScrollPane.background", WORKSPACE_BG);
        UIManager.put("Viewport.background", WORKSPACE_BG);

        UIManager.put("OptionPane.background", Color.WHITE);
        UIManager.put("OptionPane.messageForeground", TEXT_PRIMARY);
        UIManager.put("OptionPane.messageFont", FONT_REGULAR);
        UIManager.put("Button.font", FONT_REGULAR_BOLD);

        UIManager.put("ToolTip.font", FONT_SMALL);
        UIManager.put("ToolTip.background", SIDEBAR_BG);
        UIManager.put("ToolTip.foreground", Color.WHITE);
    }

    /**
     * Creates a rounded card panel with standard padding and subtle border.
     */
    public static JPanel createCardPanel() {
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(CARD_BG);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2.setColor(CARD_BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(new EmptyBorder(18, 20, 18, 20));
        return card;
    }

    /**
     * Creates a styled text field with explicit high-contrast foreground, background, and padding.
     */
    public static JTextField createTextField() {
        JTextField field = new JTextField();
        field.setFont(FONT_REGULAR);
        field.setForeground(INPUT_FG);
        field.setBackground(INPUT_BG);
        field.setCaretColor(INPUT_FG);
        field.setBorder(new CompoundBorder(
                new LineBorder(INPUT_BORDER, 1, true),
                new EmptyBorder(8, 10, 8, 10)
        ));
        field.setPreferredSize(new Dimension(field.getPreferredSize().width, 38));
        return field;
    }

    /**
     * Creates a styled combo box with explicit high-contrast foreground and background.
     */
    public static <E> JComboBox<E> createComboBox() {
        JComboBox<E> box = new JComboBox<>();
        box.setFont(FONT_REGULAR);
        box.setForeground(INPUT_FG);
        box.setBackground(INPUT_BG);
        box.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel lbl = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                lbl.setFont(FONT_REGULAR);
                lbl.setBorder(new EmptyBorder(6, 10, 6, 10));
                if (isSelected) {
                    lbl.setBackground(PRIMARY_BLUE);
                    lbl.setForeground(Color.WHITE);
                } else {
                    lbl.setBackground(Color.WHITE);
                    lbl.setForeground(TEXT_PRIMARY);
                }
                return lbl;
            }
        });
        box.setPreferredSize(new Dimension(box.getPreferredSize().width, 38));
        return box;
    }

    /**
     * Creates a styled primary action button with generous click target.
     */
    public static JButton createPrimaryButton(String text) {
        return createStyledButton(text, PRIMARY_BLUE, PRIMARY_BLUE_HOVER, Color.WHITE);
    }

    /**
     * Creates a secondary/neutral button.
     */
    public static JButton createSecondaryButton(String text) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed()) {
                    g2.setColor(new Color(226, 232, 240));
                } else if (getModel().isRollover()) {
                    g2.setColor(new Color(241, 245, 249));
                } else {
                    g2.setColor(Color.WHITE);
                }
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 6, 6);
                g2.setColor(CARD_BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 6, 6);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(FONT_REGULAR_BOLD);
        btn.setForeground(TEXT_PRIMARY);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(10, 18, 10, 18));
        return btn;
    }

    /**
     * Creates a danger/destructive button.
     */
    public static JButton createDangerButton(String text) {
        return createStyledButton(text, DANGER_RED, new Color(185, 28, 28), Color.WHITE);
    }

    /**
     * Creates a success button.
     */
    public static JButton createSuccessButton(String text) {
        return createStyledButton(text, SUCCESS_GREEN, new Color(21, 128, 61), Color.WHITE);
    }

    private static JButton createStyledButton(String text, Color normalColor, Color hoverColor, Color textColor) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (!isEnabled()) {
                    g2.setColor(new Color(203, 213, 225));
                } else if (getModel().isPressed()) {
                    g2.setColor(hoverColor.darker());
                } else if (getModel().isRollover()) {
                    g2.setColor(hoverColor);
                } else {
                    g2.setColor(normalColor);
                }
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 6, 6);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(FONT_REGULAR_BOLD);
        btn.setForeground(textColor);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(10, 20, 10, 20));
        return btn;
    }

    /**
     * Applies styling to a JTable for clean, readable presentation with comfortable 38px rows.
     */
    public static void styleTable(JTable table) {
        table.setRowHeight(38);
        table.setFont(FONT_REGULAR);
        table.setForeground(TEXT_PRIMARY);
        table.setBackground(CARD_BG);
        table.setGridColor(TABLE_GRID);
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(true);
        table.setSelectionBackground(TABLE_SELECTION);
        table.setSelectionForeground(TEXT_PRIMARY);

        JTableHeader header = table.getTableHeader();
        header.setFont(FONT_SMALL_BOLD);
        header.setForeground(TEXT_SECONDARY);
        header.setBackground(TABLE_HEADER_BG);
        header.setPreferredSize(new Dimension(0, 40));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, CARD_BORDER));

        ((DefaultTableCellRenderer) header.getDefaultRenderer()).setHorizontalAlignment(SwingConstants.LEFT);
    }

    /**
     * Creates a badge label with a rounded colored pill background.
     */
    public static JLabel createBadge(String text, Color bg, Color fg) {
        JLabel label = new JLabel(text, SwingConstants.CENTER) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(bg);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
                g2.setColor(new Color(bg.getRed(), bg.getGreen(), bg.getBlue(), 120));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        label.setFont(FONT_SMALL_BOLD);
        label.setForeground(fg);
        label.setBorder(new EmptyBorder(4, 12, 4, 12));
        label.setOpaque(false);
        return label;
    }

    /**
     * Creates an informative step header with a numbered pill badge and explanatory guide text.
     */
    public static JPanel createStepHeader(int stepNumber, String title, String description) {
        JPanel headerPanel = new JPanel(new BorderLayout(12, 4));
        headerPanel.setOpaque(false);

        JLabel stepBadge = createBadge("STEP " + stepNumber, PRIMARY_BLUE, Color.WHITE);
        headerPanel.add(stepBadge, BorderLayout.WEST);

        JPanel textGroup = new JPanel();
        textGroup.setLayout(new BoxLayout(textGroup, BoxLayout.Y_AXIS));
        textGroup.setOpaque(false);

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(FONT_HEADER);
        titleLabel.setForeground(TEXT_PRIMARY);

        JLabel descLabel = new JLabel("<html><body style='width: 580px;'>" + description + "</body></html>");
        descLabel.setFont(FONT_SMALL);
        descLabel.setForeground(TEXT_SECONDARY);

        textGroup.add(titleLabel);
        textGroup.add(Box.createVerticalStrut(2));
        textGroup.add(descLabel);

        headerPanel.add(textGroup, BorderLayout.CENTER);
        return headerPanel;
    }

    /**
     * Creates an alert/banner panel for informative messages.
     */
    public static JPanel createBanner(String message, Color bgColor, Color borderColor, Color textColor, String symbol) {
        JPanel banner = new JPanel(new BorderLayout(14, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(bgColor);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2.setColor(borderColor);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2.dispose();
            }
        };
        banner.setOpaque(false);
        banner.setBorder(new EmptyBorder(12, 16, 12, 16));

        JLabel symLabel = new JLabel(symbol);
        symLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        symLabel.setForeground(textColor);

        JLabel textLabel = new JLabel("<html><body style='width: 600px;'>" + message + "</body></html>");
        textLabel.setFont(FONT_REGULAR);
        textLabel.setForeground(textColor);

        banner.add(symLabel, BorderLayout.WEST);
        banner.add(textLabel, BorderLayout.CENTER);
        return banner;
    }
}
