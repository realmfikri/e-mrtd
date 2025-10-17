package emu.ui;

import emu.SimLogCategory;

final class LogEntry {

  private final SimLogCategory category;
  private final String source;
  private final String message;

  LogEntry(SimLogCategory category, String source, String message) {
    this.category = category;
    this.source = source;
    this.message = message;
  }

  SimLogCategory getCategory() {
    return category;
  }

  String getSource() {
    return source;
  }

  String getMessage() {
    return message;
  }
}

