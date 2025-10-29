package emu.ui;

import emu.IssuerSimulator;
import emu.PersonalizationJob;
import emu.SimConfig;
import emu.SimLogCategory;
import emu.SimPhase;
import emu.SimRunner;
import emu.SessionReport;

import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.icao.MRZInfo;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScenarioRunnerIntegrationTest {

  @Test
  void issuerPresetFeedsReadDg1WithIssuedData() throws Exception {
    Path issuerOutput = Files.createTempDirectory("scenario-runner-issuer");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of(
            "--output=" + issuerOutput,
            "--disable-dg=14",
            "--disable-dg=15",
            "--no-ta",
            "--lifecycle=PERSONALIZED",
            "--lifecycle=LOCKED"),
        false);
    ScenarioStep readStep = new ScenarioStep(
        "Read passport",
        "emu.ReadDG1Main",
        List.of("--seed"),
        true);
    ScenarioPreset preset = new ScenarioPreset(
        "Issuer + Read",
        "Personalise via issuer simulator then reuse the card for ReadDG1.",
        List.of(issuerStep, readStep));

    AdvancedOptionsSnapshot options = new AdvancedOptionsSnapshot(
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        List.<String>of(),
        null,
        null,
        null,
        false,
        false,
        List.<Integer>of(),
        List.<Integer>of(),
        null,
        null,
        List.<String>of(),
        null,
        null,
        null,
        null);

    ScenarioRunner runner = new ScenarioRunner();
    RecordingListener listener = new RecordingListener();

    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    ScenarioStep issuerScenarioStep = preset.getSteps().get(0);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerScenarioStep, options, listener);
    assertNotNull(issuerResult, "Issuer personalization should produce a result");

    ScenarioStep readScenarioStep = preset.getSteps().get(1);
    Path reportPath = Files.createTempFile("scenario-runner", ".json");
    Method buildConfig = ScenarioRunner.class.getDeclaredMethod(
        "buildSimConfig", ScenarioStep.class, AdvancedOptionsSnapshot.class, Path.class, IssuerSimulator.Result.class);
    buildConfig.setAccessible(true);
    SimConfig config = (SimConfig) buildConfig.invoke(runner, readScenarioStep, options, reportPath, issuerResult);
    assertSame(issuerResult, config.issuerResult, "SimConfig should retain issuer artifacts");

    Method runSim = ScenarioRunner.class.getDeclaredMethod(
        "runSimStep", ScenarioStep.class, SimConfig.class, IssuerSimulator.Result.class, ScenarioExecutionListener.class);
    runSim.setAccessible(true);
    SessionReport report = (SessionReport) runSim.invoke(runner, readScenarioStep, config, issuerResult, listener);
    assertNotNull(report, "Read step should emit a session report");

    PersonalizationJob job = issuerResult.getJob();
    MRZInfo issuedMrz = job.getMrzInfo();
    SessionReport.MrzSummary readMrz = report.dataGroups.getDg1Mrz();

    assertNotNull(readMrz, "DG1 summary should be populated");
    assertEquals(issuedMrz.getDocumentNumber(), readMrz.documentNumber);
    assertEquals(issuedMrz.getDateOfBirth(), readMrz.dateOfBirth);
    assertEquals(issuedMrz.getDateOfExpiry(), readMrz.dateOfExpiry);
    assertEquals(issuedMrz.getPrimaryIdentifier(), readMrz.primaryIdentifier);
    assertEquals(issuedMrz.getSecondaryIdentifier(), readMrz.secondaryIdentifier);

    Path dg2Path = issuerResult.getOutputDirectory().resolve("EF.DG2.bin");
    assertTrue(Files.exists(dg2Path), "Issuer should export DG2 artifacts");
    byte[] issuedDg2 = Files.readAllBytes(dg2Path);

    SessionReport.Dg2Metadata dg2Metadata = report.dataGroups.getDg2Metadata();
    assertNotNull(dg2Metadata, "DG2 metadata should be present in the report");
    assertEquals(issuedDg2.length, dg2Metadata.length, "DG2 byte length must align with issuer artifact");
    assertFalse(dg2Metadata.faces.isEmpty(), "DG2 metadata should describe face imagery");

    try (ByteArrayInputStream in = new ByteArrayInputStream(issuedDg2)) {
      DG2File issuerDg2 = new DG2File(in);
      FaceInfo faceInfo = issuerDg2.getFaceInfos().get(0);
      FaceImageInfo imageInfo = faceInfo.getFaceImageInfos().get(0);
      SessionReport.Dg2FaceSummary summary = dg2Metadata.faces.get(0);
      assertEquals(imageInfo.getWidth(), summary.width);
      assertEquals(imageInfo.getHeight(), summary.height);
      assertEquals(imageInfo.getMimeType(), summary.mimeType);
    }
  }

  private static final class RecordingListener implements ScenarioExecutionListener {
    final List<String> logs = new ArrayList<>();
    final List<SimPhase> phases = new ArrayList<>();
    SessionReport lastReport;

    @Override
    public void onLog(SimLogCategory category, String source, String message) {
      logs.add("[" + Instant.now() + "] " + category + "/" + source + ": " + message);
    }

    @Override
    public void onPhase(SimPhase phase, String detail) {
      phases.add(phase);
    }

    @Override
    public void onReport(SessionReport report) {
      this.lastReport = report;
    }
  }
}
