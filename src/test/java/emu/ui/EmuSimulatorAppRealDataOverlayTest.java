package emu.ui;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import emu.RealPassportProfile;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.scene.control.Label;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EmuSimulatorAppRealDataOverlayTest {

  static {
    System.setProperty("java.awt.headless", "true");
    System.setProperty("prism.order", "sw");
  }

  private static final AtomicBoolean FX_INITIALIZED = new AtomicBoolean();
  private static volatile boolean fxAvailable = true;

  @BeforeAll
  static void startFxToolkit() throws Exception {
    if (FX_INITIALIZED.compareAndSet(false, true)) {
      CountDownLatch latch = new CountDownLatch(1);
      try {
        Platform.startup(latch::countDown);
        if (!latch.await(5, TimeUnit.SECONDS)) {
          fxAvailable = false;
        }
      } catch (Throwable ex) {
        fxAvailable = false;
      }
    }
  }

  @Test
  void warningTogglesWhenRealDataOverlayArmed() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    EmuSimulatorApp app = new EmuSimulatorApp();

    Label warningLabel = extractLabel(app, "realDataOverlayWarningLabel");

    AtomicReference<Boolean> visible = new AtomicReference<>();
    CountDownLatch initialLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      visible.set(warningLabel.isVisible());
      initialLatch.countDown();
    });
    if (!initialLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for initial visibility state");
    }
    assertFalse(visible.get(), "Overlay warning should be hidden by default");

    RealPassportProfile profile = new RealPassportProfile(
        "X1234567",
        "010101",
        "300101",
        Map.of(1, new byte[] {0x01}),
        new byte[] {0x02},
        new byte[] {0x03},
        new byte[] {0x04});

    CountDownLatch copyLatch = new CountDownLatch(1);
    AtomicReference<Throwable> error = new AtomicReference<>();
    Platform.runLater(() -> {
      try {
        setField(app, "lastRealPassportProfile", profile);
        invoke(app, "copyRealPassportProfileToSimulator");
      } catch (Throwable t) {
        error.set(t);
      } finally {
        copyLatch.countDown();
      }
    });
    if (!copyLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out queuing real data overlay");
    }
    if (error.get() != null) {
      fail(error.get());
    }

    AtomicReference<String> warningText = new AtomicReference<>();
    CountDownLatch armedLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      warningText.set(warningLabel.getText());
      visible.set(warningLabel.isVisible());
      armedLatch.countDown();
    });
    if (!armedLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for overlay warning after copy");
    }
    assertTrue(visible.get(), "Overlay warning should become visible when armed");
    assertNotNull(warningText.get(), "Overlay warning text should be populated");
    assertTrue(
        warningText.get().contains("Terminal Authentication"),
        "Overlay warning should explain that authentication keys are not copied");

    CountDownLatch disarmLatch = new CountDownLatch(1);
    AtomicReference<Throwable> disarmError = new AtomicReference<>();
    Platform.runLater(() -> {
      try {
        invoke(app, "setRealDataOverlayArmed", false);
      } catch (Throwable t) {
        disarmError.set(t);
      } finally {
        disarmLatch.countDown();
      }
    });
    if (!disarmLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out disarming real data overlay");
    }
    if (disarmError.get() != null) {
      fail(disarmError.get());
    }

    CountDownLatch clearedLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      visible.set(warningLabel.isVisible());
      clearedLatch.countDown();
    });
    if (!clearedLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for overlay warning to hide");
    }
    assertFalse(visible.get(), "Overlay warning should hide after disarming");
  }

  private static Label extractLabel(EmuSimulatorApp app, String fieldName) throws Exception {
    java.lang.reflect.Field field = EmuSimulatorApp.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return (Label) field.get(app);
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static void invoke(Object target, String methodName, Object... args) throws Exception {
    Class<?>[] types = new Class<?>[args.length];
    for (int i = 0; i < args.length; i++) {
      types[i] = args[i] instanceof Boolean ? boolean.class : args[i].getClass();
    }
    java.lang.reflect.Method method = target.getClass().getDeclaredMethod(methodName, types);
    method.setAccessible(true);
    method.invoke(target, args);
  }
}
