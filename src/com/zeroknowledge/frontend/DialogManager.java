package com.zeroknowledge.frontend;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Standardized dialogs for user confirmations, error reporting, warnings,
 * and informative notices without exposing raw stack traces or cryptographic keys.
 */
public final class DialogManager {

    private DialogManager() {}

    /**
     * Shows a confirmation dialog with clear Yes/No options.
     */
    public static boolean showConfirmation(Component parent, String title, String message, String confirmButtonText) {
        JPanel panel = new JPanel(new BorderLayout(12, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel iconLabel = new JLabel("?");
        iconLabel.setFont(new Font("SansSerif", Font.BOLD, 28));
        iconLabel.setForeground(ThemeManager.PRIMARY_BLUE);

        JLabel msgLabel = new JLabel("<html><body style='width: 320px; font-family: sans-serif; font-size: 11pt; color: #0F172A;'>"
                + message + "</body></html>");

        panel.add(iconLabel, BorderLayout.WEST);
        panel.add(msgLabel, BorderLayout.CENTER);

        Object[] options = {confirmButtonText != null ? confirmButtonText : "Proceed", "Cancel"};
        int result = JOptionPane.showOptionDialog(
                parent,
                panel,
                title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );
        return result == JOptionPane.YES_OPTION;
    }

    /**
     * Shows an error dialog with actionable guidance.
     */
    public static void showError(Component parent, String title, String message) {
        JPanel panel = new JPanel(new BorderLayout(12, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel iconLabel = new JLabel("✕");
        iconLabel.setFont(new Font("SansSerif", Font.BOLD, 26));
        iconLabel.setForeground(ThemeManager.DANGER_RED);

        JLabel msgLabel = new JLabel("<html><body style='width: 340px; font-family: sans-serif; font-size: 11pt; color: #0F172A;'>"
                + message + "</body></html>");

        panel.add(iconLabel, BorderLayout.WEST);
        panel.add(msgLabel, BorderLayout.CENTER);

        JOptionPane.showMessageDialog(
                parent,
                panel,
                title,
                JOptionPane.ERROR_MESSAGE
        );
    }

    /**
     * Shows a warning dialog.
     */
    public static void showWarning(Component parent, String title, String message) {
        JPanel panel = new JPanel(new BorderLayout(12, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel iconLabel = new JLabel("⚠");
        iconLabel.setFont(new Font("SansSerif", Font.BOLD, 26));
        iconLabel.setForeground(ThemeManager.WARNING_AMBER);

        JLabel msgLabel = new JLabel("<html><body style='width: 340px; font-family: sans-serif; font-size: 11pt; color: #0F172A;'>"
                + message + "</body></html>");

        panel.add(iconLabel, BorderLayout.WEST);
        panel.add(msgLabel, BorderLayout.CENTER);

        JOptionPane.showMessageDialog(
                parent,
                panel,
                title,
                JOptionPane.WARNING_MESSAGE
        );
    }

    /**
     * Shows an informational dialog.
     */
    public static void showInfo(Component parent, String title, String message) {
        JPanel panel = new JPanel(new BorderLayout(12, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel iconLabel = new JLabel("ℹ");
        iconLabel.setFont(new Font("SansSerif", Font.BOLD, 26));
        iconLabel.setForeground(ThemeManager.PRIMARY_BLUE);

        JLabel msgLabel = new JLabel("<html><body style='width: 340px; font-family: sans-serif; font-size: 11pt; color: #0F172A;'>"
                + message + "</body></html>");

        panel.add(iconLabel, BorderLayout.WEST);
        panel.add(msgLabel, BorderLayout.CENTER);

        JOptionPane.showMessageDialog(
                parent,
                panel,
                title,
                JOptionPane.INFORMATION_MESSAGE
        );
    }
}
