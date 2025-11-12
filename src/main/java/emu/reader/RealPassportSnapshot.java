package emu.reader;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable snapshot of LDS content retrieved from a real passport.
 */
public final class RealPassportSnapshot {

    private final String documentNumber;
    private final String dateOfBirth;
    private final String dateOfExpiry;
    private final String mrz;
    private final String fullName;
    private final String nationality;
    private final String imageMime;
    private final byte[] imageBytes;
    private final Map<Integer, byte[]> dataGroupBytes;
    private final byte[] comFile;
    private final byte[] sodFile;
    private final byte[] cardAccessFile;

    public RealPassportSnapshot(
            String documentNumber,
            String dateOfBirth,
            String dateOfExpiry,
            String mrz,
            String fullName,
            String nationality,
            String imageMime,
            byte[] imageBytes,
            Map<Integer, byte[]> dataGroupBytes,
            byte[] comFile,
            byte[] sodFile,
            byte[] cardAccessFile) {
        this.documentNumber = documentNumber;
        this.dateOfBirth = dateOfBirth;
        this.dateOfExpiry = dateOfExpiry;
        this.mrz = mrz;
        this.fullName = fullName;
        this.nationality = nationality;
        this.imageMime = imageMime;
        this.imageBytes = copy(imageBytes);
        this.dataGroupBytes = Collections.unmodifiableMap(copyMap(dataGroupBytes));
        this.comFile = copy(comFile);
        this.sodFile = copy(sodFile);
        this.cardAccessFile = copy(cardAccessFile);
    }

    public String documentNumber() {
        return documentNumber;
    }

    public String dateOfBirth() {
        return dateOfBirth;
    }

    public String dateOfExpiry() {
        return dateOfExpiry;
    }

    public String mrz() {
        return mrz;
    }

    public String fullName() {
        return fullName;
    }

    public String nationality() {
        return nationality;
    }

    public String imageMime() {
        return imageMime;
    }

    public byte[] imageBytes() {
        return imageBytes;
    }

    public boolean isValid() {
        return mrz != null && !mrz.isBlank();
    }

    public byte[] safeImageBytes() {
        return copy(imageBytes);
    }

    public Map<Integer, byte[]> dataGroupBytes() {
        Map<Integer, byte[]> copy = new HashMap<>();
        for (Map.Entry<Integer, byte[]> entry : dataGroupBytes.entrySet()) {
            copy.put(entry.getKey(), copy(entry.getValue()));
        }
        return Collections.unmodifiableMap(copy);
    }

    public byte[] dataGroupBytes(int dataGroupNumber) {
        byte[] bytes = dataGroupBytes.get(dataGroupNumber);
        return copy(bytes);
    }

    public byte[] comFile() {
        return copy(comFile);
    }

    public byte[] sodFile() {
        return copy(sodFile);
    }

    public byte[] cardAccessFile() {
        return copy(cardAccessFile);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        RealPassportSnapshot that = (RealPassportSnapshot) o;
        return Objects.equals(documentNumber, that.documentNumber)
                && Objects.equals(dateOfBirth, that.dateOfBirth)
                && Objects.equals(dateOfExpiry, that.dateOfExpiry)
                && Objects.equals(mrz, that.mrz)
                && Objects.equals(fullName, that.fullName)
                && Objects.equals(nationality, that.nationality)
                && Objects.equals(imageMime, that.imageMime)
                && Arrays.equals(imageBytes, that.imageBytes)
                && mapsEqual(dataGroupBytes, that.dataGroupBytes)
                && Arrays.equals(comFile, that.comFile)
                && Arrays.equals(sodFile, that.sodFile)
                && Arrays.equals(cardAccessFile, that.cardAccessFile);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(documentNumber, dateOfBirth, dateOfExpiry, mrz, fullName, nationality, imageMime);
        result = 31 * result + Arrays.hashCode(imageBytes);
        result = 31 * result + mapHash(dataGroupBytes);
        result = 31 * result + Arrays.hashCode(comFile);
        result = 31 * result + Arrays.hashCode(sodFile);
        result = 31 * result + Arrays.hashCode(cardAccessFile);
        return result;
    }

    @Override
    public String toString() {
        return "RealPassportSnapshot{"
                + "documentNumber='" + documentNumber + '\''
                + ", dateOfBirth='" + dateOfBirth + '\''
                + ", dateOfExpiry='" + dateOfExpiry + '\''
                + ", mrz='" + mrz + '\''
                + ", fullName='" + fullName + '\''
                + ", nationality='" + nationality + '\''
                + ", imageMime='" + imageMime + '\''
                + ", imageBytes=" + describeBytes(imageBytes)
                + ", dataGroupBytes=" + describeMap(dataGroupBytes)
                + ", comFile=" + describeBytes(comFile)
                + ", sodFile=" + describeBytes(sodFile)
                + ", cardAccessFile=" + describeBytes(cardAccessFile)
                + '}';
    }

    private static byte[] copy(byte[] bytes) {
        return bytes == null ? null : Arrays.copyOf(bytes, bytes.length);
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

    private static boolean mapsEqual(Map<Integer, byte[]> a, Map<Integer, byte[]> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (Map.Entry<Integer, byte[]> entry : a.entrySet()) {
            byte[] other = b.get(entry.getKey());
            if (!Arrays.equals(entry.getValue(), other)) {
                return false;
            }
        }
        return true;
    }

    private static int mapHash(Map<Integer, byte[]> map) {
        int hash = 0;
        for (Map.Entry<Integer, byte[]> entry : map.entrySet()) {
            hash += Objects.hash(entry.getKey(), Arrays.hashCode(entry.getValue()));
        }
        return hash;
    }

    private static String describeBytes(byte[] bytes) {
        return bytes == null ? "null" : ("byte[" + bytes.length + "]");
    }

    private static String describeMap(Map<Integer, byte[]> map) {
        if (map.isEmpty()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<Integer, byte[]> entry : map.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(entry.getKey()).append('=').append(describeBytes(entry.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }
}
