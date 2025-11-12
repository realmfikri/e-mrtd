package emu;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.jmrtd.lds.icao.MRZInfo;

/**
 * Utility helpers for working with MRZ content.
 */
public final class MrzUtil {

  private static final int TD1_DOC_NUMBER_START = 5;
  private static final int TD1_DOC_NUMBER_LENGTH = 9;
  private static final int TD3_DOC_NUMBER_LENGTH = 9;
  private static final char FILLER_CHARACTER = '<';

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
    if (!hasText(docNumber)) {
      return null;
    }
    String documentType;
    try {
      documentType = mrzInfo.getDocumentCode();
    } catch (Exception ex) {
      documentType = null;
    }
    return ensureDocumentNumberLength(docNumber, documentType);
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

  /**
   * Removes trailing filler characters ({@code <}) that are commonly appended to MRZ fields when the
   * underlying value is shorter than the allotted space.
   */
  public static String stripTrailingFillers(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    int end = trimmed.length();
    while (end > 0 && trimmed.charAt(end - 1) == FILLER_CHARACTER) {
      end--;
    }
    if (end == trimmed.length()) {
      return trimmed;
    }
    return trimmed.substring(0, end);
  }

  /**
   * Returns the typical MRZ document number length for the supplied document type.
   *
   * <p>Most travel documents – passports (TD3), visas (TD2) and ID cards (TD1) – allocate nine
   * characters to the document number field. The UI and simulators treat that as the default while
   * still tolerating longer custom values supplied by callers.</p>
   */
  public static int defaultDocumentNumberLength(String documentType) {
    if (documentType == null || documentType.isBlank()) {
      return TD3_DOC_NUMBER_LENGTH;
    }
    String normalized = documentType.trim().toUpperCase(Locale.ROOT);
    if (normalized.startsWith("P")
        || normalized.startsWith("V")
        || normalized.startsWith("I")
        || normalized.startsWith("AC")
        || normalized.startsWith("C")) {
      return TD3_DOC_NUMBER_LENGTH;
    }
    return TD3_DOC_NUMBER_LENGTH;
  }

  /**
   * Pads the supplied document number with MRZ filler characters ({@code <}) so that it matches the
   * typical field length for the provided document type.
   */
  public static String ensureDocumentNumberLength(String value, String documentType) {
    return ensureDocumentNumberLength(value, defaultDocumentNumberLength(documentType));
  }

  /**
   * Pads the supplied document number with MRZ filler characters ({@code <}) until it reaches the
   * requested length. Values that already meet or exceed the target length are returned unchanged.
   */
  public static String ensureDocumentNumberLength(String value, int targetLength) {
    if (!hasText(value) || targetLength <= 0) {
      return value;
    }
    StringBuilder builder = new StringBuilder(value.trim());
    while (builder.length() < targetLength) {
      builder.append(FILLER_CHARACTER);
    }
    return builder.toString();
  }

  /**
   * Convenience overload that pads the supplied document number to the default MRZ length (nine
   * characters).
   */
  public static String ensureDocumentNumberLength(String value) {
    return ensureDocumentNumberLength(value, TD3_DOC_NUMBER_LENGTH);
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

