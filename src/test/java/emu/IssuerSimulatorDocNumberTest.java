package emu;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuerSimulatorDocNumberTest {

  @Test
  void fullLdsScenarioHandlesShortDocumentNumbers() throws Exception {
    IssuerJobBuilder builder = new IssuerJobBuilder();
    builder.consumeArguments(java.util.List.of(
        "--doc-number", "X5215910",
        "--lifecycle", "SIMULATOR",
        "--lifecycle", "PERSONALIZED",
        "--lifecycle", "LOCKED"));
    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(builder.buildJob(), builder.buildSimulatorOptions());
    assertNotNull(result, "Issuer simulator should return a result");
    assertTrue(Files.exists(result.getOutputDirectory()), "Output directory should be created");
  }
}
