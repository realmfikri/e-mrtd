package emu.ui;

import java.util.List;

final class ScenarioPreset {

  private final String name;
  private final String description;
  private final List<ScenarioStep> steps;

  ScenarioPreset(String name, String description, List<ScenarioStep> steps) {
    this.name = name;
    this.description = description;
    this.steps = List.copyOf(steps);
  }

  String getName() {
    return name;
  }

  String getDescription() {
    return description;
  }

  List<ScenarioStep> getSteps() {
    return steps;
  }
}

