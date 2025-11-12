package emu;

import org.jmrtd.lds.icao.MRZInfo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IssuerJobBuilderTest {

  @Test
  void padsDocumentNumberWhenConsumedFromArguments() throws Exception {
    IssuerJobBuilder builder = new IssuerJobBuilder();
    builder.consumeArguments(List.of("--doc-number", "X5215910"));
    PersonalizationJob job = builder.buildJob();
    MRZInfo mrzInfo = job.getMrzInfo();
    assertEquals(
        "X5215910<",
        MrzUtil.deriveDocumentNumber(mrzInfo),
        "Issuer MRZ should be padded to nine characters");
  }
}
