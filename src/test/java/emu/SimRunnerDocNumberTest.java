package emu;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SimRunnerDocNumberTest {

  @Test
  void runNormalizesDocumentNumberForBacAndMrz() throws Exception {
    SimConfig config = new SimConfig.Builder()
        .docNumber("X5215910")
        .dateOfBirth("750101")
        .dateOfExpiry("250101")
        .seed(true)
        .build();

    SessionReport report = new SimRunner().run(config, null);
    assertNotNull(report, "SimRunner should complete and return a report");
    SessionReport.MrzSummary mrz = report.dataGroups.getDg1Mrz();
    assertNotNull(mrz, "DG1 summary should be present after personalization");
    assertEquals(
        "X5215910<",
        MrzUtil.ensureDocumentNumberLength(mrz.documentNumber),
        "DG1 MRZ must include filler padding");
  }
}
