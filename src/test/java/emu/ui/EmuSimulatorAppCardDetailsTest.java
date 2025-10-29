package emu.ui;

import emu.IssuerSimulator;
import javafx.application.Platform;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.imageio.ImageIO;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class EmuSimulatorAppCardDetailsTest {

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
  void cardDetailsTabLoadsTerminalPortraitWhenPreviewPresent() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    Path preview = createTestImage();
    SessionReportViewData viewData = new SessionReportViewData(
        "ISO7816",
        "PACE",
        true,
        true,
        true,
        false,
        false,
        false,
        null,
        "PASS",
        "SHA256",
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        null,
        null,
        null,
        List.of(),
        false,
        false,
        preview.toString(),
        null);

    EmuSimulatorApp app = new EmuSimulatorApp();

    Method updateMethod = EmuSimulatorApp.class.getDeclaredMethod(
        "updateCardDetailsTab", SessionReportViewData.class, IssuerSimulator.Result.class);
    updateMethod.setAccessible(true);

    Field terminalImageField = EmuSimulatorApp.class.getDeclaredField("terminalFacePreviewImage");
    terminalImageField.setAccessible(true);
    ImageView terminalImage = (ImageView) terminalImageField.get(app);

    AtomicReference<Throwable> error = new AtomicReference<>();
    CountDownLatch invokeLatch = new CountDownLatch(1);
    CountDownLatch imageLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      terminalImage.imageProperty().addListener((obs, oldImg, newImg) -> {
        if (newImg != null) {
          imageLatch.countDown();
        }
      });
      try {
        updateMethod.invoke(app, viewData, null);
      } catch (Throwable t) {
        error.set(t);
        imageLatch.countDown();
      } finally {
        invokeLatch.countDown();
      }
    });

    if (!invokeLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for JavaFX invocation");
    }
    if (!imageLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for terminal portrait to load");
    }
    if (error.get() != null) {
      fail(error.get());
    }

    AtomicReference<Image> loadedImage = new AtomicReference<>();
    CountDownLatch readLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      loadedImage.set(terminalImage.getImage());
      readLatch.countDown();
    });
    if (!readLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out retrieving loaded terminal portrait");
    }

    assertNotNull(loadedImage.get(), "Terminal portrait should load when preview path is present");
  }

  @Test
  void cardDetailsTabLoadsIssuerPortraitFromViewData() throws Exception {
    assumeTrue(fxAvailable, "JavaFX toolkit unavailable in headless environment");

    Path preview = createTestImage();
    SessionReportViewData viewData = new SessionReportViewData(
        "ISO7816",
        "PACE",
        true,
        true,
        true,
        false,
        false,
        false,
        null,
        "PASS",
        "SHA256",
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        null,
        null,
        null,
        List.of(),
        false,
        false,
        null,
        preview.toString());

    EmuSimulatorApp app = new EmuSimulatorApp();

    Method updateMethod = EmuSimulatorApp.class.getDeclaredMethod(
        "updateCardDetailsTab", SessionReportViewData.class, IssuerSimulator.Result.class);
    updateMethod.setAccessible(true);

    Field cardImageField = EmuSimulatorApp.class.getDeclaredField("cardPortraitImage");
    cardImageField.setAccessible(true);
    ImageView cardImage = (ImageView) cardImageField.get(app);

    AtomicReference<Throwable> error = new AtomicReference<>();
    CountDownLatch invokeLatch = new CountDownLatch(1);
    CountDownLatch imageLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      cardImage.imageProperty().addListener((obs, oldImg, newImg) -> {
        if (newImg != null) {
          imageLatch.countDown();
        }
      });
      try {
        updateMethod.invoke(app, viewData, null);
      } catch (Throwable t) {
        error.set(t);
        imageLatch.countDown();
      } finally {
        invokeLatch.countDown();
      }
    });

    if (!invokeLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for JavaFX invocation");
    }
    if (!imageLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out waiting for issuer portrait to load");
    }
    if (error.get() != null) {
      fail(error.get());
    }

    AtomicReference<Image> loadedImage = new AtomicReference<>();
    CountDownLatch readLatch = new CountDownLatch(1);
    Platform.runLater(() -> {
      loadedImage.set(cardImage.getImage());
      readLatch.countDown();
    });
    if (!readLatch.await(5, TimeUnit.SECONDS)) {
      fail("Timed out retrieving loaded issuer portrait");
    }

    assertNotNull(loadedImage.get(), "Issuer portrait should load from session report metadata when available");
  }

  private static Path createTestImage() throws Exception {
    BufferedImage image = new BufferedImage(4, 4, BufferedImage.TYPE_INT_RGB);
    Graphics2D graphics = image.createGraphics();
    graphics.setColor(Color.BLUE);
    graphics.fillRect(0, 0, 4, 4);
    graphics.dispose();
    Path path = Files.createTempFile("dg2-preview", ".png");
    ImageIO.write(image, "png", path.toFile());
    return path;
  }
}
