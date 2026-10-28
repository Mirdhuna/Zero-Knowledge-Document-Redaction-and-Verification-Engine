package com.zeroknowledge.frontend;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Centralized theme, color palette, typography, and UI component styling.
 * Uses only standard JDK AWT and Swing APIs with custom painting.
 */
public final class ThemeManager {

    private ThemeManager() {}

    // Color Palette
    public static final Color SIDEBAR_BG = new Color(22, 27, 34);           // Dark charcoal / navy
    public static final Color SIDEBAR_HOVER = new Color(38, 48, 64);
    public static final Color SIDEBAR_ACTIVE = new Color(44, 57, 75);
    public static final Color SIDEBAR_TEXT = new Color(203, 213, 225);
    public static final Color SIDEBAR_TEXT_MUTED = new Color(148, 163, 184);

    public static final Color WORKSPACE_BG = new Color(248, 250, 252);     // Very light slate/grey
    public static final Color CARD_BG = new Color(255, 255, 255);          // Pure white
    public static final Color CARD_BORDER = new Color(226, 232, 240);      // Light grey border
    public static final Color CARD_BORDER_FOCUSED = new Color(148, 163, 184);

    public static final Color PRIMARY_BLUE = new Color(2, 132, 199);       // Muted teal/blue
    public static final Color PRIMARY_BLUE_HOVER = new Color(3, 105, 161);
    public static final Color PRIMARY_BLUE_ACTIVE = new Color(7, 89, 133);

    public static final Color SUCCESS_GREEN = new Color(22, 163, 74);      // Verified/Completed
    public static final Color SUCCESS_BG = new Color(240, 253, 244);
    public static final Color SUCCESS_BORDER = new Color(187, 247, 208);

    public static final Color WARNING_AMBER = new Color(217, 119, 6);      // Warnings/Pending
    public static final Color WARNING_BG = new Color(254, 252, 232);
    public static final Color WARNING_BORDER = new Color(254, 240, 138);

    public static final Color DANGER_RED = new Color(220, 38, 38);         // Failed/Destructive
    public static final Color DANGER_BG = new Color(254, 242, 242);
    public static final Color DANGER_BORDER = new Color(254, 202, 202);

    public static final Color TEXT_PRIMARY = new Color(15, 23, 42);        // Dark slate
    public static final Color TEXT_SECONDARY = new Color(71, 85, 105);     // Medium slate
    public static final Color TEXT_MUTED = new Color(148, 163, 184);       // Light slate

    public static final Color TABLE_HEADER_BG = new Color(241, 245, 249);
    public static final Color TABLE_ROW_ALT = new Color(248, 250, 252);
    public static final Color TABLE_GRID = new Color(226, 232, 240);
    public static final Color TABLE_SELECTION = new Color(224, 242, 254);

    // Fonts
    public static final Font FONT_TITLE = new Font("SansSerif", Font.BOLD, 20);
    public static final Font FONT_HEADER = new Font("SansSerif", Font.BOLD, 16);
    public static final Font FONT_SUBHEADER = new Font("SansSerif", Font.BOLD, 14);
    public static final Font FONT_REGULAR = new Font("SansSerif", Font.PLAIN, 13);
    public static final Font FONT_REGULAR_BOLD = new Font("SansSerif", Font.BOLD, 13);
    public static final Font FONT_SMALL = new Font("SansSerif", Font.PLAIN, 12);
    public static final Font FONT_SMALL_BOLD = new Font("SansSerif", Font.BOLD, 12);
    public static final Font FONT_MONO = new Font("Monospaced", Font.PLAIN, 12);
    public static final Font FONT_MONO_BOLD = new Font("Monospaced", Font.BOLD, 12);

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
        card.setBorder(new EmptyBorder(16, 18, 16, 18));
        return card;
    }

    /**
     * Creates a styled primary action button.
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
        btn.setBorder(new EmptyBorder(8, 16, 8, 16));
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
        btn.setBorder(new EmptyBorder(8, 18, 8, 18));
        return btn;
    }

    /**
     * Applies styling to a JTable for clean, readable presentation.
     */
    public static void styleTable(JTable table) {
        table.setRowHeight(32);
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
        header.setPreferredSize(new Dimension(0, 36));
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
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g2.setColor(new Color(bg.getRed(), bg.getGreen(), bg.getBlue(), 120));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        label.setFont(FONT_SMALL_BOLD);
        label.setForeground(fg);
        label.setBorder(new EmptyBorder(3, 10, 3, 10));
        label.setOpaque(false);
        return label;
    }

    /**
     * Creates an alert/banner panel for informative messages.
     */
    public static JPanel createBanner(String message, Color bgColor, Color borderColor, Color textColor, String symbol) {
        JPanel banner = new JPanel(new BorderLayout(12, 0)) {
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
        banner.setBorder(new EmptyBorder(10, 14, 10, 14));

        JLabel symLabel = new JLabel(symbol);
        symLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        symLabel.setForeground(textColor);

        JLabel textLabel = new JLabel("<html>" + message + "</html>");
        textLabel.setFont(FONT_REGULAR);
        textLabel.setForeground(textColor);

        banner.add(symLabel, BorderLayout.WEST);
        banner.add(textLabel, BorderLayout.CENTER);
        return banner;
    }
}
