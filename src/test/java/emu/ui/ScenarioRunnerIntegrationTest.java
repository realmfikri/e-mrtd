package emu.ui;

import emu.IssuerSimulator;
import emu.PersonalizationJob;
import emu.SimConfig;
import emu.SimLogCategory;
import emu.SimPhase;
import emu.SimRunner;
import emu.SessionReport;

import javafx.concurrent.Task;
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

    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

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
    Path expectedTrust = issuerResult.getOutputDirectory().resolve("CSCA.cer");
    assertTrue(config.trustMasterListPaths.contains(expectedTrust),
        "Issuer CSCA should be wired as a trust source when reusing artifacts");

    Method runSim = ScenarioRunner.class.getDeclaredMethod(
        "runSimStep",
        SimRunner.class,
        ScenarioStep.class,
        SimConfig.class,
        IssuerSimulator.Result.class,
        ScenarioExecutionListener.class);
    runSim.setAccessible(true);
    SessionReport report =
        (SessionReport) runSim.invoke(runner, new SimRunner(), readScenarioStep, config, issuerResult, listener);
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
    assertNotNull(dg2Metadata.previewPath, "DG2 preview path should be captured");
    assertTrue(Files.exists(Path.of(dg2Metadata.previewPath)), "DG2 preview file should exist on disk");
    issuerResult.getFacePreviewPath().ifPresent(path -> {
      assertNotNull(dg2Metadata.issuerPreviewPath, "Issuer preview path should be captured when issuer artifacts are reused");
      assertEquals(path.toAbsolutePath().toString(), dg2Metadata.issuerPreviewPath);
      assertTrue(
          Files.exists(Path.of(dg2Metadata.issuerPreviewPath)),
          "Issuer preview file should exist on disk");
    });

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

  @Test
  void readOnlyScenarioReusesPreviousIssuerResult() throws Exception {
    Path issuerOutput = Files.createTempDirectory("scenario-runner-issuer-reuse");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of(
            "--output=" + issuerOutput,
            "--primary-id=TESTER",
            "--secondary-id=AGENT",
            "--lifecycle=PERSONALIZED",
            "--lifecycle=LOCKED"),
        false);

    ScenarioRunner runner = new ScenarioRunner();
    RecordingListener listener = new RecordingListener();
    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerStep, options, listener);
    assertNotNull(issuerResult, "Issuer preset should yield a result");

    ScenarioStep readStep = new ScenarioStep(
        "Read passport",
        "emu.ReadDG1Main",
        List.of("--seed"),
        true);
    ScenarioPreset readPreset = new ScenarioPreset(
        "Read only",
        "Reuse issuer artifacts to read DG1 without reissuing",
        List.of(readStep));

    Path reportPath = Files.createTempFile("scenario-runner-reuse", ".json");
    Task<ScenarioResult> task = runner.createTask(readPreset, options, reportPath, listener, issuerResult);
    Method call = task.getClass().getDeclaredMethod("call");
    call.setAccessible(true);
    ScenarioResult result = (ScenarioResult) call.invoke(task);

    assertTrue(result.isSuccess(), "Read-only scenario should succeed");
    assertTrue(result.getIssuerResult().isPresent(), "Final issuer result should carry over");
    assertSame(issuerResult, result.getIssuerResult().get(), "Issuer result should be reused");

    MRZInfo issuedMrz = issuerResult.getJob().getMrzInfo();
    assertEquals("TESTER", issuedMrz.getPrimaryIdentifier());
    assertEquals("AGENT", issuedMrz.getSecondaryIdentifier());

    SessionReport report = result.getReport();
    assertNotNull(report, "Session report should be captured from read scenario");
    SessionReport.MrzSummary mrz = report.dataGroups.getDg1Mrz();
    assertNotNull(mrz, "DG1 MRZ summary should be present");

    assertEquals(issuedMrz.getPrimaryIdentifier(), mrz.primaryIdentifier);
    assertEquals(issuedMrz.getSecondaryIdentifier(), mrz.secondaryIdentifier);
    assertEquals(issuedMrz.getDocumentNumber(), mrz.documentNumber);
    assertEquals(issuedMrz.getDateOfBirth(), mrz.dateOfBirth);
    assertEquals(issuedMrz.getDateOfExpiry(), mrz.dateOfExpiry);
  }

  @Test
  void terminalAuthArgsReuseIssuerWhenNotMarkedFresh() throws Exception {
    Path issuerOutput = Files.createTempDirectory("scenario-runner-issuer-ta-reuse");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of("--output=" + issuerOutput, "--lifecycle=PERSONALIZED"),
        false);

    ScenarioRunner runner = new ScenarioRunner();
    RecordingListener listener = new RecordingListener();
    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerStep, options, listener);

    ScenarioStep taReadStep = new ScenarioStep(
        "TA Read",
        "emu.ReadDG1Main",
        List.of(
            "--seed",
            "--attempt-pace",
            "--ta-cvc=" + Files.createTempFile("ta", ".cvc"),
            "--ta-key=" + Files.createTempFile("ta", ".key")),
        true);

    Method resolveReuse = ScenarioRunner.class.getDeclaredMethod(
        "resolveIssuerReuse", ScenarioStep.class, IssuerSimulator.Result.class, ScenarioExecutionListener.class);
    resolveReuse.setAccessible(true);
    IssuerSimulator.Result resolved =
        (IssuerSimulator.Result) resolveReuse.invoke(runner, taReadStep, issuerResult, listener);

    assertSame(issuerResult, resolved, "TA scenarios should reuse issuer personalization unless marked fresh");
  }

  @Test
  void freshCardScenarioSkipsIssuerReuse() throws Exception {
    Path issuerOutput = Files.createTempDirectory("scenario-runner-issuer-ta-skip");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of("--output=" + issuerOutput, "--lifecycle=PERSONALIZED"),
        false);

    ScenarioRunner runner = new ScenarioRunner();
    RecordingListener listener = new RecordingListener();
    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerStep, options, listener);

    ScenarioStep taReadStep = new ScenarioStep(
        "TA Read",
        "emu.ReadDG1Main",
        List.of(
            "--seed",
            "--attempt-pace",
            "--ta-cvc=" + Files.createTempFile("ta", ".cvc"),
            "--ta-key=" + Files.createTempFile("ta", ".key")),
        true,
        true);

    Method resolveReuse = ScenarioRunner.class.getDeclaredMethod(
        "resolveIssuerReuse", ScenarioStep.class, IssuerSimulator.Result.class, ScenarioExecutionListener.class);
    resolveReuse.setAccessible(true);
    IssuerSimulator.Result resolved =
        (IssuerSimulator.Result) resolveReuse.invoke(runner, taReadStep, issuerResult, listener);

    assertNull(resolved, "Steps marked as fresh should not reuse issuer personalization");
  }

  @Test
  void passiveAuthPresetsRequestFreshCardsWhenIssuerCached() throws Exception {
    ScenarioRunner runner = new ScenarioRunner();
    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

    Path issuerOutput = Files.createTempDirectory("scenario-runner-passive-issuer");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of("--output=" + issuerOutput, "--lifecycle=PERSONALIZED", "--lifecycle=LOCKED"),
        false);

    RecordingListener issuerListener = new RecordingListener();
    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerStep, options, issuerListener);

    List<String> presetNames = List.of(
        "Passive Authentication (tamper detection)",
        "Passive Authentication (missing trust anchors)");

    for (String presetName : presetNames) {
      ScenarioPreset preset = ScenarioPresets.all().stream()
          .filter(p -> p.getName().equals(presetName))
          .findFirst()
          .orElseThrow(() -> new IllegalStateException("Missing preset " + presetName));

      RecordingListener listener = new RecordingListener();
      Path reportPath = Files.createTempFile("scenario-runner-passive", ".json");
      Task<ScenarioResult> task = runner.createTask(preset, options, reportPath, listener, issuerResult);

      Method call = task.getClass().getDeclaredMethod("call");
      call.setAccessible(true);
      ScenarioResult result = (ScenarioResult) call.invoke(task);

      assertFalse(result.isSuccess(), presetName + " should fail when Passive Authentication errors are expected");
      assertEquals("Run ReadDG1Main", result.getFailedStep(), "Read step should be marked as failed");
      assertTrue(
          listener.logs.stream().anyMatch(log -> log.contains("cached issuer result will not be reused")),
          "Scenario should skip cached issuer personalization for " + presetName);
    }
  }

  @Test
  void issuerScenarioRecoversAfterPassiveFailure() throws Exception {
    ScenarioRunner runner = new ScenarioRunner();
    AdvancedOptionsSnapshot options = emptyAdvancedOptions();

    Path issuerOutput = Files.createTempDirectory("scenario-runner-issuer-recovery");
    ScenarioStep issuerStep = new ScenarioStep(
        "Issue document",
        "emu.IssuerMain",
        List.of("--output=" + issuerOutput, "--lifecycle=PERSONALIZED", "--lifecycle=LOCKED"),
        false);

    RecordingListener issuerListener = new RecordingListener();
    Method runIssuer = ScenarioRunner.class.getDeclaredMethod(
        "runIssuerStep", ScenarioStep.class, AdvancedOptionsSnapshot.class, ScenarioExecutionListener.class);
    runIssuer.setAccessible(true);
    IssuerSimulator.Result issuerResult =
        (IssuerSimulator.Result) runIssuer.invoke(runner, issuerStep, options, issuerListener);

    ScenarioPreset passivePreset = ScenarioPresets.all().stream()
        .filter(p -> p.getName().equals("Passive Authentication (tamper detection)"))
        .findFirst()
        .orElseThrow();

    RecordingListener passiveListener = new RecordingListener();
    Path passiveReport = Files.createTempFile("scenario-runner-passive-recovery", ".json");
    Task<ScenarioResult> passiveTask = runner.createTask(passivePreset, options, passiveReport, passiveListener, issuerResult);
    Method call = passiveTask.getClass().getDeclaredMethod("call");
    call.setAccessible(true);
    ScenarioResult passiveResult = (ScenarioResult) call.invoke(passiveTask);
    assertFalse(passiveResult.isSuccess(), "Passive preset should fail to simulate corruption");
    assertTrue(
        passiveListener.logs.stream().anyMatch(log -> log.contains("cached issuer result will not be reused")),
        "Passive preset should skip cached issuer personalization");

    ScenarioPreset issuerPreset = ScenarioPresets.all().stream()
        .filter(p -> p.getName().equals("Issuer: Full LDS"))
        .findFirst()
        .orElseThrow();

    RecordingListener recoveryListener = new RecordingListener();
    Path recoveryReport = Files.createTempFile("scenario-runner-issuer-recovery", ".json");
    Task<ScenarioResult> issuerTask = runner.createTask(issuerPreset, options, recoveryReport, recoveryListener, issuerResult);
    ScenarioResult recoveryResult = (ScenarioResult) call.invoke(issuerTask);

    assertTrue(recoveryResult.isSuccess(), "Issuer scenario should succeed after passive failure");
    assertTrue(
        recoveryResult.getIssuerResult().isPresent(),
        "Issuer scenario should produce a personalization result");
  }

  private static AdvancedOptionsSnapshot emptyAdvancedOptions() {
    return new AdvancedOptionsSnapshot(
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
