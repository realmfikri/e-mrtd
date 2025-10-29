package emu.ui;

import emu.IssuerJobBuilder;
import emu.IssuerSimulator;
import emu.SessionReport;
import emu.SimConfig;
import emu.SimEvents;
import emu.SimLogCategory;
import emu.SimPhase;
import emu.SimRunner;
import javafx.concurrent.Task;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class ScenarioRunner {

  private static final String READ_MAIN_CLASS = "emu.ReadDG1Main";
  private static final String ISSUER_MAIN_CLASS = "emu.IssuerMain";
  private static final String MISSING_TRUST_STORE_DIR = "target/ui-missing-trust";
  private static final String DEFAULT_DOC = "123456789";
  private static final String DEFAULT_DOB = "750101";
  private static final String DEFAULT_DOE = "250101";

  private final Path projectDirectory = Paths.get("").toAbsolutePath();
  private final String javaExecutable;
  private final SimRunner simRunner = new SimRunner();

  ScenarioRunner() {
    String javaHome = System.getProperty("java.home");
    javaExecutable = Paths.get(javaHome, "bin", "java").toString();
  }

  Task<ScenarioResult> createTask(
      ScenarioPreset preset,
      AdvancedOptionsSnapshot advancedOptions,
      Path reportPath,
      ScenarioExecutionListener listener) {
    Objects.requireNonNull(preset, "preset");
    Objects.requireNonNull(advancedOptions, "advancedOptions");
    Objects.requireNonNull(reportPath, "reportPath");
    Objects.requireNonNull(listener, "listener");

    boolean prepareMissingTrustStore = shouldPrepareMissingTrustStore(preset, advancedOptions);

    return new Task<>() {
      @Override
      protected ScenarioResult call() throws Exception {
        if (prepareMissingTrustStore) {
          prepareMissingTrustStoreDirectory();
        }

        Path parent = reportPath.getParent();
        if (parent != null) {
          Files.createDirectories(parent);
        }
        Files.deleteIfExists(reportPath);

        List<String> executedCommands = new ArrayList<>();
        int exitCode = 0;
        String failedStep = null;
        SessionReport finalReport = null;
        IssuerSimulator.Result finalIssuerResult = null;

        for (ScenarioStep step : preset.getSteps()) {
          if (isCancelled()) {
            break;
          }

          List<String> command = buildCommand(step, advancedOptions, reportPath);
          executedCommands.add(String.join(" ", command));

          if (READ_MAIN_CLASS.equals(step.getMainClass())) {
            try {
              SimConfig config = buildSimConfig(step, advancedOptions, reportPath);
              finalReport = runSimStep(step, config, listener);
            } catch (Exception e) {
              listener.onLog(SimLogCategory.GENERAL, step.getName(), "Error: " + e.getMessage());
              exitCode = 1;
              failedStep = step.getName();
              break;
            }
          } else if (ISSUER_MAIN_CLASS.equals(step.getMainClass())) {
            try {
              IssuerSimulator.Result issuerResult = runIssuerStep(step, advancedOptions, listener);
              finalIssuerResult = issuerResult;
            } catch (Exception e) {
              listener.onLog(SimLogCategory.GENERAL, step.getName(), "Error: " + e.getMessage());
              exitCode = 1;
              failedStep = step.getName();
              break;
            }
          } else {
            exitCode = runProcessStep(step, command, listener);
            if (exitCode != 0) {
              failedStep = step.getName();
              break;
            }
          }
        }

        boolean success = exitCode == 0 && !isCancelled();
        return new ScenarioResult(
            success,
            exitCode,
            failedStep,
            executedCommands,
            reportPath,
            finalReport,
            finalIssuerResult);
      }
    };
  }

  private List<String> buildCommand(
      ScenarioStep step,
      AdvancedOptionsSnapshot advancedOptions,
      Path reportPath) {
    List<String> command = new ArrayList<>();
    command.add(javaExecutable);
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(step.getMainClass());

    List<String> args = new ArrayList<>(step.getArgs());
    if (step.isProducesSessionReport()) {
      args.add("--out=" + reportPath.toString());
      args.addAll(advancedOptions.toArgs());
    } else if (READ_MAIN_CLASS.equals(step.getMainClass())) {
      args.addAll(advancedOptions.toArgs());
    } else if (ISSUER_MAIN_CLASS.equals(step.getMainClass())) {
      args.addAll(buildIssuerAdvancedArgs(advancedOptions));
    }
    command.addAll(args);
    return command;
  }

  private boolean shouldPrepareMissingTrustStore(ScenarioPreset preset, AdvancedOptionsSnapshot options) {
    if (options.getTrustStorePath() != null && !options.getTrustStorePath().isBlank()) {
      return false;
    }
    for (ScenarioStep step : preset.getSteps()) {
      for (String arg : step.getArgs()) {
        if (arg.startsWith("--trust-store=") && arg.endsWith(MISSING_TRUST_STORE_DIR)) {
          return true;
        }
      }
    }
    return false;
  }

  private void prepareMissingTrustStoreDirectory() throws IOException {
    Path dir = projectDirectory.resolve(MISSING_TRUST_STORE_DIR);
    if (Files.exists(dir)) {
      try (Stream<Path> stream = Files.walk(dir)) {
        List<Path> toDelete = stream
            .filter(path -> !path.equals(dir))
            .sorted(Comparator.comparingInt(Path::getNameCount).reversed())
            .collect(Collectors.toList());
        for (Path path : toDelete) {
          Files.deleteIfExists(path);
        }
      }
    }
    Files.createDirectories(dir);
  }

  private SessionReport runSimStep(ScenarioStep step, SimConfig config, ScenarioExecutionListener listener) throws Exception {
    UiSimEvents events = new UiSimEvents(listener, step.getName());
    SessionReport report = simRunner.run(config, events);
    listener.onReport(report);
    return report;
  }

  private IssuerSimulator.Result runIssuerStep(
      ScenarioStep step,
      AdvancedOptionsSnapshot advancedOptions,
      ScenarioExecutionListener listener) throws Exception {
    List<String> args = new ArrayList<>(step.getArgs());
    args.addAll(buildIssuerAdvancedArgs(advancedOptions));

    IssuerJobBuilder builder = new IssuerJobBuilder();
    builder.consumeArguments(args);

    if (builder.isHelpRequested()) {
      listener.onLog(SimLogCategory.GENERAL, step.getName(), "Help requested; skipping issuer run");
      return null;
    }

    IssuerSimulator simulator = new IssuerSimulator();
    listener.onLog(SimLogCategory.GENERAL, step.getName(), "Starting issuer personalization");
    IssuerSimulator.Result result = simulator.run(builder.buildJob(), builder.buildSimulatorOptions());
    builder.report(result, message -> listener.onLog(SimLogCategory.GENERAL, step.getName(), message));
    listener.onLog(SimLogCategory.GENERAL, step.getName(), "Issuer personalization completed");
    return result;
  }

  private int runProcessStep(ScenarioStep step, List<String> command, ScenarioExecutionListener listener)
      throws IOException, InterruptedException {
    listener.onLog(SimLogCategory.GENERAL, step.getName(), "$ " + String.join(" ", command));
    ProcessBuilder pb = new ProcessBuilder(command);
    pb.directory(projectDirectory.toFile());
    pb.redirectErrorStream(true);
    Process process = pb.start();
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        listener.onLog(SimLogCategory.GENERAL, step.getName(), line);
      }
    }
    return process.waitFor();
  }

  private SimConfig buildSimConfig(
      ScenarioStep step,
      AdvancedOptionsSnapshot options,
      Path reportPath) {
    SimConfig.Builder builder = new SimConfig.Builder()
        .docNumber(DEFAULT_DOC)
        .dateOfBirth(DEFAULT_DOB)
        .dateOfExpiry(DEFAULT_DOE)
        .terminalAuthDate(LocalDate.now(ZoneOffset.UTC))
        .reportOutput(reportPath);

    Path previewDir = reportPath.getParent() != null
        ? reportPath.getParent().resolve("faces")
        : Paths.get("target", "ui-faces");
    builder.facePreviewDirectory(previewDir);

    applyStepArgs(builder, step.getArgs());
    options.applyToBuilder(builder);
    return builder.build();
  }

  private void applyStepArgs(SimConfig.Builder builder, List<String> args) {
    for (String arg : args) {
      if ("--seed".equals(arg)) {
        builder.seed(true);
      } else if ("--attempt-pace".equals(arg)) {
        builder.attemptPace(true);
      } else if (arg.startsWith("--pace-prefer=")) {
        builder.pacePreference(arg.substring("--pace-prefer=".length()));
      } else if ("--require-pa".equals(arg)) {
        builder.requirePa(true);
      } else if ("--require-aa".equals(arg) || "--aa".equals(arg)) {
        builder.requireAa(true);
      } else if ("--corrupt-dg2".equals(arg)) {
        builder.corruptDg2(true);
      } else if ("--large-dg2".equals(arg)) {
        builder.largeDg2(true);
      } else if (arg.startsWith("--trust-store=") || arg.startsWith("--trust=")) {
        String value = arg.contains("--trust-store=")
            ? arg.substring("--trust-store=".length())
            : arg.substring("--trust=".length());
        builder.trustStorePath(Paths.get(value));
      } else if (arg.startsWith("--trust-ml=")) {
        builder.trustMasterList(Paths.get(arg.substring("--trust-ml=".length())));
      } else if (arg.startsWith("--ta-cvc=")) {
        builder.addTaCvc(Paths.get(arg.substring("--ta-cvc=".length())));
      } else if (arg.startsWith("--ta-key=")) {
        builder.taKey(Paths.get(arg.substring("--ta-key=".length())));
      } else if (arg.startsWith("--ta-date=")) {
        builder.terminalAuthDate(resolveTerminalAuthDate(arg.substring("--ta-date=".length())));
      } else if (arg.startsWith("--can=")) {
        builder.can(arg.substring("--can=".length()));
      } else if (arg.startsWith("--pin=")) {
        builder.pin(arg.substring("--pin=".length()));
      } else if (arg.startsWith("--puk=")) {
        builder.puk(arg.substring("--puk=".length()));
      } else if ("--open-com-sod".equals(arg)) {
        builder.openComSodReads(true);
      } else if ("--secure-com-sod".equals(arg)) {
        builder.openComSodReads(false);
      }
    }
  }

  private static LocalDate resolveTerminalAuthDate(String override) {
    LocalDate defaultDate = LocalDate.now(ZoneOffset.UTC);
    if (override == null || override.isBlank()) {
      return defaultDate;
    }
    String trimmed = override.trim();
    try {
      return LocalDate.parse(trimmed, DateTimeFormatter.ISO_LOCAL_DATE);
    } catch (Exception ignored) {
      // continue
    }
    String digitsOnly = trimmed.replaceAll("[^0-9]", "");
    if (digitsOnly.length() == 8) {
      int year = Integer.parseInt(digitsOnly.substring(0, 4));
      int month = Integer.parseInt(digitsOnly.substring(4, 6));
      int day = Integer.parseInt(digitsOnly.substring(6, 8));
      return LocalDate.of(year, month, day);
    }
    if (digitsOnly.length() == 6) {
      int year = Integer.parseInt(digitsOnly.substring(0, 2));
      int month = Integer.parseInt(digitsOnly.substring(2, 4));
      int day = Integer.parseInt(digitsOnly.substring(4, 6));
      int centuryBase = defaultDate.getYear() / 100 * 100;
      int fullYear = centuryBase + year;
      if (fullYear < defaultDate.getYear() - 50) {
        fullYear += 100;
      } else if (fullYear > defaultDate.getYear() + 50) {
        fullYear -= 100;
      }
      return LocalDate.of(fullYear, month, day);
    }
    return defaultDate;
  }

  private List<String> buildIssuerAdvancedArgs(AdvancedOptionsSnapshot options) {
    List<String> args = new ArrayList<>();
    if (hasText(options.getDocumentNumber())) {
      args.add("--doc-number=" + options.getDocumentNumber());
    }
    if (hasText(options.getDateOfBirth())) {
      args.add("--date-of-birth=" + options.getDateOfBirth());
    }
    if (hasText(options.getDateOfExpiry())) {
      args.add("--date-of-expiry=" + options.getDateOfExpiry());
    }
    if (hasText(options.getCan())) {
      args.add("--pace-can=" + options.getCan());
    }
    if (hasText(options.getPin())) {
      args.add("--pace-pin=" + options.getPin());
    }
    if (hasText(options.getPuk())) {
      args.add("--pace-puk=" + options.getPuk());
    }
    for (Integer dg : options.getIssuerEnableDataGroups()) {
      args.add("--enable-dg=" + dg);
    }
    for (Integer dg : options.getIssuerDisableDataGroups()) {
      args.add("--disable-dg=" + dg);
    }
    if (hasText(options.getIssuerDigestAlgorithm())) {
      args.add("--digest=" + options.getIssuerDigestAlgorithm());
    }
    if (hasText(options.getIssuerSignatureAlgorithm())) {
      args.add("--signature=" + options.getIssuerSignatureAlgorithm());
    }
    for (String lifecycle : options.getIssuerLifecycleTargets()) {
      if (hasText(lifecycle)) {
        args.add("--lifecycle=" + lifecycle);
      }
    }
    Boolean openRead = options.getIssuerOpenRead();
    if (openRead != null) {
      args.add("--open-read=" + openRead);
    }
    return args;
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  private static final class UiSimEvents implements SimEvents {
    private final ScenarioExecutionListener listener;
    private final String source;

    UiSimEvents(ScenarioExecutionListener listener, String source) {
      this.listener = listener;
      this.source = source;
    }

    @Override
    public void onPhase(SimPhase phase, String detail) {
      listener.onPhase(phase, detail);
    }

    @Override
    public void onLog(SimLogCategory category, String message) {
      listener.onLog(category, source, message);
    }
  }
}

