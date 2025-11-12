package emu;

import static org.junit.jupiter.api.Assertions.assertEquals;

import net.sf.scuba.data.Gender;
import org.jmrtd.lds.icao.MRZInfo;
import org.junit.jupiter.api.Test;

class MRZInfoBehaviorTest {
  @Test
  void deriveDocumentNumberPadsMrzInfoValues() {
    MRZInfo info = new MRZInfo("P<", "UTO", "TEST", "PERSON", "X5215910", "UTO", "030804", Gender.MALE, "300224", "");
    assertEquals("X5215910<", MrzUtil.deriveDocumentNumber(info));
  }
}
