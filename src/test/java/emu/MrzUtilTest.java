package emu;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MrzUtilTest {

  @Test
  void padsDocumentNumberToDefaultLength() {
    assertEquals("X5215910<", MrzUtil.ensureDocumentNumberLength("X5215910"));
    assertEquals("X5215910<", MrzUtil.ensureDocumentNumberLength("X5215910", 9));
  }

  @Test
  void preservesExistingPadding() {
    assertEquals("X5215910<", MrzUtil.ensureDocumentNumberLength("X5215910<"));
  }

  @Test
  void returnsNullWhenValueMissing() {
    assertNull(MrzUtil.ensureDocumentNumberLength(null));
  }

  @Test
  void resolvesDefaultLengthForCommonDocumentTypes() {
    assertEquals(9, MrzUtil.defaultDocumentNumberLength("P<"));
    assertEquals(9, MrzUtil.defaultDocumentNumberLength("ID"));
    assertEquals(9, MrzUtil.defaultDocumentNumberLength("AC"));
    assertEquals(9, MrzUtil.defaultDocumentNumberLength(""));
  }
}
