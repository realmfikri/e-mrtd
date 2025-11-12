package emu;

import org.jmrtd.lds.icao.MRZInfo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Utility encoding helpers shared by issuer workflows for PUT-DATA payloads.
 */
final class IssuerSecretEncoder {

  private static final int TAG_MRZ_CONTAINER = 0x62;
  private static final int TAG_DOC_NUMBER = 0x5F1F;
  private static final int TAG_DATE_OF_BIRTH = 0x5F18;
  private static final int TAG_DATE_OF_EXPIRY = 0x5F19;
  private static final int TAG_PACE_SECRET_ENTRY = 0x66;

  static final byte KEY_REFERENCE_CAN = 0x02;
  static final byte KEY_REFERENCE_PIN = 0x03;
  static final byte KEY_REFERENCE_PUK = 0x04;

  private IssuerSecretEncoder() {
  }

  static byte[] encodeMrzSeed(MRZInfo mrzInfo) {
    Objects.requireNonNull(mrzInfo, "mrzInfo");
    String paddedDocumentNumber =
        MrzUtil.ensureDocumentNumberLength(mrzInfo.getDocumentNumber(), mrzInfo.getDocumentCode());
    return encodeMrzSeed(
        paddedDocumentNumber,
        mrzInfo.getDateOfBirth(),
        mrzInfo.getDateOfExpiry());
  }

  static byte[] encodeMrzSeed(String documentNumber, String dateOfBirth, String dateOfExpiry) {
    Objects.requireNonNull(documentNumber, "documentNumber");
    Objects.requireNonNull(dateOfBirth, "dateOfBirth");
    Objects.requireNonNull(dateOfExpiry, "dateOfExpiry");

    byte[] docBytes = documentNumber.getBytes(StandardCharsets.US_ASCII);
    byte[] dobBytes = dateOfBirth.getBytes(StandardCharsets.US_ASCII);
    byte[] doeBytes = dateOfExpiry.getBytes(StandardCharsets.US_ASCII);

    ByteArrayOutputStream inner = new ByteArrayOutputStream();
    writeTag(inner, TAG_DOC_NUMBER);
    writeLength(inner, docBytes.length);
    inner.write(docBytes, 0, docBytes.length);

    writeTag(inner, TAG_DATE_OF_BIRTH);
    writeLength(inner, dobBytes.length);
    inner.write(dobBytes, 0, dobBytes.length);

    writeTag(inner, TAG_DATE_OF_EXPIRY);
    writeLength(inner, doeBytes.length);
    inner.write(doeBytes, 0, doeBytes.length);

    byte[] innerBytes = inner.toByteArray();
    ByteArrayOutputStream outer = new ByteArrayOutputStream();
    outer.write(TAG_MRZ_CONTAINER);
    writeLength(outer, innerBytes.length);
    outer.write(innerBytes, 0, innerBytes.length);
    return outer.toByteArray();
  }

  static byte[] encodePaceSecrets(String can, String pin, String puk) {
    ByteArrayOutputStream entries = new ByteArrayOutputStream();
    appendPaceSecretEntry(entries, KEY_REFERENCE_CAN, can);
    appendPaceSecretEntry(entries, KEY_REFERENCE_PIN, pin);
    appendPaceSecretEntry(entries, KEY_REFERENCE_PUK, puk);

    byte[] entryBytes = entries.toByteArray();
    return entryBytes.length == 0 ? null : entryBytes;
  }

  private static void appendPaceSecretEntry(ByteArrayOutputStream out, byte keyReference, String value) {
    if (!hasText(value)) {
      return;
    }
    byte[] valueBytes = value.getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream entry = new ByteArrayOutputStream();
    entry.write(keyReference);
    entry.write(valueBytes, 0, valueBytes.length);
    byte[] entryBytes = entry.toByteArray();
    writeTag(out, TAG_PACE_SECRET_ENTRY);
    writeLength(out, entryBytes.length);
    out.write(entryBytes, 0, entryBytes.length);
  }

  private static void writeTag(ByteArrayOutputStream out, int tag) {
    if (tag > 0xFF) {
      out.write((tag >> 8) & 0xFF);
    }
    out.write(tag & 0xFF);
  }

  private static void writeLength(ByteArrayOutputStream out, int length) {
    if (length < 0x80) {
      out.write(length);
    } else {
      int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
      out.write(0x80 | numBytes);
      for (int i = numBytes - 1; i >= 0; i--) {
        out.write((length >> (8 * i)) & 0xFF);
      }
    }
  }

  private static boolean hasText(String value) {
    return value != null && !value.isEmpty();
  }
}
