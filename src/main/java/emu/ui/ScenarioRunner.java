package emu.ui;

import javafx.concurrent.Task;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

final class ScenarioRunner {

  private static final String READ_MAIN_CLASS = "emu.ReadDG1Main";

  private final Path projectDirectory = Paths.get("").toAbsolutePath();
  private final String javaExecutable;

  ScenarioRunner() {
    String javaHome = System.getProperty("java.home");
    javaExecutable = Paths.get(javaHome, "bin", "java").toString();
  }

  Task<ScenarioResult> createTask(
      ScenarioPreset preset,
      AdvancedOptionsSnapshot advancedOptions,
      Path reportPath,
      Consumer<String> logConsumer) {
    Objects.requireNonNull(preset, "preset");
    Objects.requireNonNull(advancedOptions, "advancedOptions");
    Objects.requireNonNull(reportPath, "reportPath");
    Objects.requireNonNull(logConsumer, "logConsumer");

    List<String> advancedArgs = advancedOptions.toArgs();

    return new Task<>() {
      @Override
      protected ScenarioResult call() throws Exception {
        Path parent = reportPath.getParent();
        if (parent != null) {
          Files.createDirectories(parent);
        }
        Files.deleteIfExists(reportPath);

        List<String> executedCommands = new ArrayList<>();
        int exitCode = 0;
        String failedStep = null;

    for (ScenarioStep step : preset.getSteps()) {
          if (isCancelled()) {
            break;
          }
          List<String> command = buildCommand(step, advancedArgs, reportPath);
          String cli = String.join(" ", command);
          executedCommands.add(cli);
          logConsumer.accept("$ " + cli);

          ProcessBuilder pb = new ProcessBuilder(command);
          pb.directory(projectDirectory.toFile());
          pb.redirectErrorStream(true);
          Process process = pb.start();

          try (BufferedReader reader = new BufferedReader(
              new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
              if (isCancelled()) {
                process.destroyForcibly();
                break;
              }
              logConsumer.accept("[" + step.getName() + "] " + line);
            }
          }

          exitCode = process.waitFor();
          if (exitCode != 0) {
            failedStep = step.getName();
            break;
          }
        }

        boolean success = exitCode == 0 && !isCancelled();
        return new ScenarioResult(success, exitCode, failedStep, executedCommands, reportPath);
      }
    };
  }

  private List<String> buildCommand(ScenarioStep step, List<String> advancedArgs, Path reportPath) {
    List<String> command = new ArrayList<>();
    command.add(javaExecutable);
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(step.getMainClass());

    List<String> args = new ArrayList<>(step.getArgs());
    if (step.isProducesSessionReport()) {
      args.add("--out=" + reportPath.toString());
      args.addAll(advancedArgs);
    } else if (READ_MAIN_CLASS.equals(step.getMainClass())) {
      args.addAll(advancedArgs);
    }
    command.addAll(args);
    return command;
  }
}

