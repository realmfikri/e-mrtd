package emu;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable value object containing LDS bytes captured from a real passport.
 */
public final class RealPassportProfile {

  private final String documentNumber;
  private final String dateOfBirth;
  private final String dateOfExpiry;
  private final Map<Integer, byte[]> dataGroupBytes;
  private final byte[] comFile;
  private final byte[] sodFile;
  private final byte[] cardAccessFile;

  public RealPassportProfile(
      String documentNumber,
      String dateOfBirth,
      String dateOfExpiry,
      Map<Integer, byte[]> dataGroupBytes,
      byte[] comFile,
      byte[] sodFile,
      byte[] cardAccessFile) {
    this.documentNumber = documentNumber;
    this.dateOfBirth = dateOfBirth;
    this.dateOfExpiry = dateOfExpiry;
    this.dataGroupBytes = Collections.unmodifiableMap(copyMap(dataGroupBytes));
    this.comFile = copy(comFile);
    this.sodFile = copy(sodFile);
    this.cardAccessFile = copy(cardAccessFile);
  }

  public String getDocumentNumber() {
    return documentNumber;
  }

  public String getDateOfBirth() {
    return dateOfBirth;
  }

  public String getDateOfExpiry() {
    return dateOfExpiry;
  }

  public Map<Integer, byte[]> getDataGroupBytes() {
    Map<Integer, byte[]> copy = new HashMap<>();
    for (Map.Entry<Integer, byte[]> entry : dataGroupBytes.entrySet()) {
      copy.put(entry.getKey(), copy(entry.getValue()));
    }
    return Collections.unmodifiableMap(copy);
  }

  public byte[] getDataGroupBytes(int dataGroupNumber) {
    return copy(dataGroupBytes.get(dataGroupNumber));
  }

  public byte[] getComFile() {
    return copy(comFile);
  }

  public byte[] getSodFile() {
    return copy(sodFile);
  }

  public byte[] getCardAccessFile() {
    return copy(cardAccessFile);
  }

  private static Map<Integer, byte[]> copyMap(Map<Integer, byte[]> source) {
    Map<Integer, byte[]> copy = new HashMap<>();
    if (source != null) {
      for (Map.Entry<Integer, byte[]> entry : source.entrySet()) {
        if (entry.getKey() != null) {
          copy.put(entry.getKey(), copy(entry.getValue()));
        }
      }
    }
    return copy;
  }

  private static byte[] copy(byte[] value) {
    return value == null ? null : value.clone();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof RealPassportProfile)) {
      return false;
    }
    RealPassportProfile that = (RealPassportProfile) o;
    return Objects.equals(documentNumber, that.documentNumber)
        && Objects.equals(dateOfBirth, that.dateOfBirth)
        && Objects.equals(dateOfExpiry, that.dateOfExpiry)
        && dataGroupBytes.equals(that.dataGroupBytes)
        && java.util.Arrays.equals(comFile, that.comFile)
        && java.util.Arrays.equals(sodFile, that.sodFile)
        && java.util.Arrays.equals(cardAccessFile, that.cardAccessFile);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(documentNumber, dateOfBirth, dateOfExpiry, dataGroupBytes);
    result = 31 * result + java.util.Arrays.hashCode(comFile);
    result = 31 * result + java.util.Arrays.hashCode(sodFile);
    result = 31 * result + java.util.Arrays.hashCode(cardAccessFile);
    return result;
  }

  @Override
  public String toString() {
    return "RealPassportProfile{"
        + "documentNumber='" + documentNumber + '\''
        + ", dateOfBirth='" + dateOfBirth + '\''
        + ", dateOfExpiry='" + dateOfExpiry + '\''
        + ", dataGroups=" + dataGroupBytes.keySet()
        + '}';
  }
}
