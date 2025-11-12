package emu;

import java.util.ArrayList;
import java.util.List;

import org.jmrtd.lds.icao.MRZInfo;

/**
 * Utility helpers for working with MRZ content.
 */
public final class MrzUtil {

  private static final int TD1_DOC_NUMBER_START = 5;
  private static final int TD1_DOC_NUMBER_LENGTH = 9;
  private static final int TD3_DOC_NUMBER_LENGTH = 9;

  private MrzUtil() {
  }

  /**
   * Attempts to derive the document number from the given MRZ information, preferring the parsed
   * {@link MRZInfo} when available before falling back to the raw MRZ string. If both sources fail
   * the provided fallback is returned.
   */
  public static String deriveDocumentNumber(MRZInfo mrzInfo, String mrzText, String fallback) {
    String fromInfo = deriveDocumentNumber(mrzInfo);
    if (hasText(fromInfo)) {
      return fromInfo;
    }
    String fromText = deriveDocumentNumber(mrzText);
    if (hasText(fromText)) {
      return fromText;
    }
    return fallback;
  }

  /**
   * Derives the document number from a parsed {@link MRZInfo} instance when possible.
   */
  public static String deriveDocumentNumber(MRZInfo mrzInfo) {
    if (mrzInfo == null) {
      return null;
    }
    String docNumber = mrzInfo.getDocumentNumber();
    return hasText(docNumber) ? docNumber : null;
  }

  /**
   * Attempts to derive the document number directly from an MRZ string representation.
   */
  public static String deriveDocumentNumber(String mrzText) {
    if (!hasText(mrzText)) {
      return null;
    }

    List<String> lines = splitLines(mrzText);
    if (lines.isEmpty()) {
      return null;
    }

    // Three-line MRZ (TD1) document numbers live on the first line positions 5-13.
    if (lines.size() >= 3) {
      String docNumber = substring(lines.get(0), TD1_DOC_NUMBER_START, TD1_DOC_NUMBER_LENGTH);
      if (hasText(docNumber)) {
        return docNumber;
      }
    }

    // Two-line MRZ (TD2/TD3) document numbers usually occupy the first 9 characters of the second
    // line. Prefer that extraction when the second line is long enough.
    if (lines.size() >= 2) {
      String line2 = lines.get(1);
      String docNumber = substring(line2, 0, TD3_DOC_NUMBER_LENGTH);
      if (hasText(docNumber)) {
        return docNumber;
      }
      // Fallback to the first line positions 5-13 when the second line is too short (e.g. TD2).
      String line1 = lines.get(0);
      docNumber = substring(line1, TD1_DOC_NUMBER_START, TD1_DOC_NUMBER_LENGTH);
      if (hasText(docNumber)) {
        return docNumber;
      }
    }

    // Final fallback: return the first 9 characters of the first line if present.
    String firstLine = lines.get(0);
    if (firstLine.length() >= TD3_DOC_NUMBER_LENGTH) {
      return firstLine.substring(0, TD3_DOC_NUMBER_LENGTH);
    }
    return null;
  }

  private static List<String> splitLines(String mrzText) {
    String[] rawLines = mrzText.split("\r?\n");
    List<String> lines = new ArrayList<>(rawLines.length);
    for (String line : rawLines) {
      if (line != null && !line.isEmpty()) {
        lines.add(line);
      }
    }
    return lines;
  }

  private static String substring(String value, int start, int length) {
    if (value == null || value.length() < start + 1) {
      return null;
    }
    int end = Math.min(value.length(), start + length);
    if (end <= start) {
      return null;
    }
    return value.substring(start, end);
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }
}

