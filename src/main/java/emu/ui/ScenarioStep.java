package emu.ui;

import java.util.List;

final class ScenarioStep {

  private final String name;
  private final String mainClass;
  private final List<String> args;
  private final boolean producesSessionReport;

  ScenarioStep(String name, String mainClass, List<String> args, boolean producesSessionReport) {
    this.name = name;
    this.mainClass = mainClass;
    this.args = List.copyOf(args);
    this.producesSessionReport = producesSessionReport;
  }

  String getName() {
    return name;
  }

  String getMainClass() {
    return mainClass;
  }

  List<String> getArgs() {
    return args;
  }

  boolean isProducesSessionReport() {
    return producesSessionReport;
  }
}

