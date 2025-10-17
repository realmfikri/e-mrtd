package emu.ui;

import java.nio.file.Path;
import java.util.List;

final class ScenarioResult {

  private final boolean success;
  private final int exitCode;
  private final String failedStep;
  private final List<String> commands;
  private final Path reportPath;

  ScenarioResult(boolean success, int exitCode, String failedStep, List<String> commands, Path reportPath) {
    this.success = success;
    this.exitCode = exitCode;
    this.failedStep = failedStep;
    this.commands = List.copyOf(commands);
    this.reportPath = reportPath;
  }

  boolean isSuccess() {
    return success;
  }

  int getExitCode() {
    return exitCode;
  }

  String getFailedStep() {
    return failedStep;
  }

  List<String> getCommands() {
    return commands;
  }

  Path getReportPath() {
    return reportPath;
  }
}

