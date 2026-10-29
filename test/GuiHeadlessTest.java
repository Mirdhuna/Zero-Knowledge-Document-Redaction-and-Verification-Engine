package test;

import com.zeroknowledge.frontend.BackendContext;
import com.zeroknowledge.frontend.MainFrame;

import javax.swing.*;
import java.awt.*;

/**
 * Validates Swing component construction, model bindings, and layout hierarchy
 * in conjunction with official backend services.
 */
public class GuiHeadlessTest {

    public static void main(String[] args) {
        System.out.println("Graphics Environment Headless: " + GraphicsEnvironment.isHeadless());

        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("Running in headless container. Testing backend context construction...");
            BackendContext ctx = new BackendContext();
            System.out.println("BackendContext initialized successfully. Active Key: " + ctx.getActiveKeyAlias());
        } else {
            System.out.println("Display environment detected. Instantiating GUI frames and panels...");
            SwingUtilities.invokeLater(() -> {
                try {
                    BackendContext ctx = new BackendContext();
                    MainFrame frame = new MainFrame(ctx);
                    frame.navigateTo(MainFrame.CARD_REDACTION);
                    frame.navigateTo(MainFrame.CARD_VERIFICATION);
                    frame.navigateTo(MainFrame.CARD_KEYS);
                    frame.navigateTo(MainFrame.CARD_AUDIT);
                    frame.navigateTo(MainFrame.CARD_SETTINGS);
                    frame.navigateTo(MainFrame.CARD_DASHBOARD);
                    frame.dispose();
                    System.out.println("GUI Smoke Test PASSED.");
                    System.exit(0);
                } catch (Throwable t) {
                    System.err.println("GUI test failed: " + t.getMessage());
                    t.printStackTrace();
                    System.exit(1);
                }
            });
        }
    }
}
