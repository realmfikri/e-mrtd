package emu.ui;

import emu.SessionReport;
import emu.SimLogCategory;
import emu.SimPhase;

interface ScenarioExecutionListener {

  void onLog(SimLogCategory category, String source, String message);

  void onPhase(SimPhase phase, String detail);

  void onReport(SessionReport report);
}

