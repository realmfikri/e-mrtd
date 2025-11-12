package emu.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import emu.RealPassportProfile;
import emu.reader.RealPassportSnapshot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EmuSimulatorAppRealDataOverlayTest {

  static {
    System.setProperty("java.awt.headless", "true");
    System.setProperty("prism.order", "sw");
  }

  private static final AtomicBoolean FX_INITIALIZED = new AtomicBoolean();
  private static volatile boolean fxAvailable = true;
  private static final byte[] ONE_PIXEL_PNG = Base64.getDecoder().decode(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABDQottAAAAABJRU5ErkJggg==");

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

  @Test
  void mrzDocumentNumberStripsTrailingPadding() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    EmuSimulatorApp app = new EmuSimulatorApp();

    String mrz = "P<UTOEXAMPLE<<PERSON<<<<<<<<<<<<<<\n" +
        "12345678<UTO9001012F3001018<<<<<<<<<<<<<<";

    RealPassportSnapshot snapshot = new RealPassportSnapshot(
        "12345678",
        "900101",
        "300101",
        mrz,
        "PERSON EXAMPLE",
        "UTO",
        null,
        null,
        Map.of(1, new byte[] {0x01}),
        null,
        null,
        null);

    CountDownLatch loadLatch = new CountDownLatch(1);
    AtomicReference<Throwable> loadError = new AtomicReference<>();
    Platform.runLater(() -> {
      try {
        invoke(app, "handleRealPassportData", snapshot);
        invoke(app, "copyRealReaderMrzToAdvanced");
      } catch (Throwable t) {
        loadError.set(t);
      } finally {
        loadLatch.countDown();
      }
    });
    if (!loadLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out applying MRZ summary from real passport data");
    }
    if (loadError.get() != null) {
      fail(loadError.get());
    }

    AdvancedOptionsPane pane = extractAdvancedOptionsPane(app);

    AtomicReference<AdvancedOptionsSnapshot> snapshotRef = new AtomicReference<>();
    CountDownLatch snapshotLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      snapshotRef.set(pane.snapshot());
      snapshotLatch.countDown();
    });
    if (!snapshotLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out capturing advanced options snapshot");
    }

    AdvancedOptionsSnapshot options = snapshotRef.get();
    assertNotNull(options, "Advanced options snapshot should be captured");
    assertEquals("12345678", options.getDocumentNumber(), "MRZ document number should strip trailing filler");
    assertEquals(8, options.getDocumentNumber().length(), "MRZ document number length should match identifier");
    assertTrue(
        options.toArgs().contains("--doc=12345678"),
        "Scenario runner arguments should include filler-free document number");
  }

  @Test
  void snapshotStripsFillersWhenUserShortensDocumentNumber() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    SessionReportViewData.MrzSummary summary = new SessionReportViewData.MrzSummary(
        "L898902C<",
        "640812",
        "120415",
        "SPECIMEN",
        "ERIKA",
        "UTO",
        "UTO");

    CountDownLatch latch = new CountDownLatch(1);
    AtomicReference<AdvancedOptionsSnapshot> snapshotRef = new AtomicReference<>();
    AtomicReference<Throwable> errorRef = new AtomicReference<>();

    String userEntry = "L898902";

    Platform.runLater(() -> {
      try {
        AdvancedOptionsPane pane = new AdvancedOptionsPane();
        pane.applyMrzSummary(summary);

        java.lang.reflect.Field field = AdvancedOptionsPane.class.getDeclaredField("docNumberField");
        field.setAccessible(true);
        TextField docField = (TextField) field.get(pane);
        docField.setText(userEntry);

        snapshotRef.set(pane.snapshot());
      } catch (Throwable t) {
        errorRef.set(t);
      } finally {
        latch.countDown();
      }
    });

    if (!latch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out capturing advanced options snapshot after user edit");
    }
    if (errorRef.get() != null) {
      fail(errorRef.get());
    }

    AdvancedOptionsSnapshot options = snapshotRef.get();
    assertNotNull(options, "Advanced options snapshot should be captured after user edit");
    assertEquals(
        userEntry,
        options.getDocumentNumber(),
        "Snapshot should retain user-entered document number without MRZ fillers");

    List<String> scenarioArgs = options.toArgs();
    assertTrue(
        scenarioArgs.contains("--doc=" + userEntry),
        "Scenario arguments should contain filler-free document number");

    ScenarioRunner runner = new ScenarioRunner();
    java.lang.reflect.Method method = ScenarioRunner.class.getDeclaredMethod(
        "buildIssuerAdvancedArgs",
        AdvancedOptionsSnapshot.class);
    method.setAccessible(true);
    @SuppressWarnings("unchecked")
    List<String> issuerArgs = (List<String>) method.invoke(runner, options);
    assertTrue(
        issuerArgs.contains("--doc-number=" + userEntry),
        "Issuer arguments should contain filler-free document number");
  }

  @Test
  void copyingMrzCopiesFaceOverridesWhenPreviewAvailable() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    EmuSimulatorApp app = new EmuSimulatorApp();

    String mrz = "P<UTOEXAMPLE<<PERSON<<<<<<<<<<<<<<\n"
        + "12345678<UTO9001012F3001018<<<<<<<<<<<<<<";

    RealPassportSnapshot snapshot = new RealPassportSnapshot(
        "12345678",
        "900101",
        "300101",
        mrz,
        "PERSON EXAMPLE",
        "UTO",
        "image/png",
        ONE_PIXEL_PNG,
        Map.of(1, new byte[] {0x01}, 2, new byte[] {0x02}),
        null,
        null,
        null);

    CountDownLatch loadLatch = new CountDownLatch(1);
    AtomicReference<Throwable> loadError = new AtomicReference<>();
    Platform.runLater(() -> {
      try {
        invoke(app, "handleRealPassportData", snapshot);
        invoke(app, "copyRealReaderMrzToAdvanced");
      } catch (Throwable t) {
        loadError.set(t);
      } finally {
        loadLatch.countDown();
      }
    });
    if (!loadLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out applying MRZ summary and copying overrides from real passport data");
    }
    if (loadError.get() != null) {
      fail(loadError.get());
    }

    AdvancedOptionsPane pane = extractAdvancedOptionsPane(app);

    AtomicReference<AdvancedOptionsSnapshot> snapshotRef = new AtomicReference<>();
    CountDownLatch snapshotLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      snapshotRef.set(pane.snapshot());
      snapshotLatch.countDown();
    });
    if (!snapshotLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out capturing advanced options snapshot after copying overrides");
    }

    AdvancedOptionsSnapshot options = snapshotRef.get();
    assertNotNull(options, "Advanced options snapshot should be captured");

    String facePath = options.getIssuerFacePath();
    assertNotNull(facePath, "Face override path should be populated");
    assertTrue(!facePath.isBlank(), "Face override path should not be blank");

    Path previewPath = Paths.get(facePath);
    assertTrue(Files.exists(previewPath), "Face preview file should exist on disk");
    try {
      assertEquals(Integer.valueOf(1), options.getIssuerFaceWidth(), "Face width should match preview image");
      assertEquals(Integer.valueOf(1), options.getIssuerFaceHeight(), "Face height should match preview image");
    } finally {
      Files.deleteIfExists(previewPath);
    }
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

  private static AdvancedOptionsPane extractAdvancedOptionsPane(EmuSimulatorApp app) throws Exception {
    java.lang.reflect.Field field = EmuSimulatorApp.class.getDeclaredField("advancedOptionsPane");
    field.setAccessible(true);
    return (AdvancedOptionsPane) field.get(app);
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
