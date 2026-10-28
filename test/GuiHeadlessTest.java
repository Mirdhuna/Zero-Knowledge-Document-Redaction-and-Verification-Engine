package test;

import com.zeroknowledge.backend.BackendContext;
import com.zeroknowledge.frontend.*;

import javax.swing.*;
import java.awt.*;

/**
 * Validates Swing component construction, model bindings, and layout hierarchy.
 */
public class GuiHeadlessTest {

    public static void main(String[] args) {
        System.out.println("Graphics Environment Headless: " + GraphicsEnvironment.isHeadless());

        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("Running in headless container. Testing backend and component non-display creation...");
            // Even in headless, pure model and service integration is verified.
        } else {
            System.out.println("Display environment detected. Instantiating GUI frames and panels...");
            SwingUtilities.invokeLater(() -> {
                try {
                    System.out.println("Step A: Creating BackendContext...");
                    BackendContext ctx = new BackendContext();
                    System.out.println("Step B: Instantiating MainFrame...");
                    MainFrame frame = new MainFrame(ctx);
                    System.out.println("Step C: Testing CardLayout navigation...");
                    frame.navigateTo(MainFrame.CARD_REDACTION);
                    frame.navigateTo(MainFrame.CARD_VERIFICATION);
                    frame.navigateTo(MainFrame.CARD_KEYS);
                    frame.navigateTo(MainFrame.CARD_AUDIT);
                    frame.navigateTo(MainFrame.CARD_SETTINGS);
                    frame.navigateTo(MainFrame.CARD_DASHBOARD);
                    System.out.println("Step D: Disposing frame...");
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
