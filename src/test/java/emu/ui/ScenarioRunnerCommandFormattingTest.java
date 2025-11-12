package emu.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

class ScenarioRunnerCommandFormattingTest {

  @Test
  void formatsCommandWithShellEscaping() {
    String formatted = ScenarioRunner.formatCommand(List.of("java", "--doc-number=L898902<"));
    assertEquals("java '--doc-number=L898902<'", formatted);
  }

  @Test
  void leavesSafeArgumentsUnquoted() {
    String formatted = ScenarioRunner.formatCommand(List.of("java", "--doc-number=ABC123"));
    assertEquals("java --doc-number=ABC123", formatted);
  }

  @Test
  void escapesSingleQuotesWithinArguments() {
    String formatted = ScenarioRunner.formatCommand(List.of("java", "O'Brien"));
    assertEquals("java 'O'\"'\"'Brien'", formatted);
  }
}
