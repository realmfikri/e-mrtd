package emu.reader;

import java.util.Arrays;
import java.util.Objects;

public final class PassportData {

    private final String documentNumber;
    private final String dateOfBirth;    // YYMMDD
    private final String dateOfExpiry;   // YYMMDD
    private final String mrz;            // teks MRZ (DG1) bisa null
    private final String fullName;       // "PRIMARY SECONDARY" dari MRZ
    private final String nationality;    // kode negara 3 huruf
    private final String imageMime;      // mime foto (jpeg/jp2/wsq) bisa null
    private final byte[] imageBytes;     // foto (boleh null)

    public PassportData(
            String documentNumber,
            String dateOfBirth,
            String dateOfExpiry,
            String mrz,
            String fullName,
            String nationality,
            String imageMime,
            byte[] imageBytes) {
        this.documentNumber = documentNumber;
        this.dateOfBirth = dateOfBirth;
        this.dateOfExpiry = dateOfExpiry;
        this.mrz = mrz;
        this.fullName = fullName;
        this.nationality = nationality;
        this.imageMime = imageMime;
        this.imageBytes = imageBytes;
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
        return imageBytes == null ? null : Arrays.copyOf(imageBytes, imageBytes.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PassportData that = (PassportData) o;
        return Objects.equals(documentNumber, that.documentNumber)
                && Objects.equals(dateOfBirth, that.dateOfBirth)
                && Objects.equals(dateOfExpiry, that.dateOfExpiry)
                && Objects.equals(mrz, that.mrz)
                && Objects.equals(fullName, that.fullName)
                && Objects.equals(nationality, that.nationality)
                && Objects.equals(imageMime, that.imageMime)
                && Arrays.equals(imageBytes, that.imageBytes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(documentNumber, dateOfBirth, dateOfExpiry, mrz, fullName, nationality, imageMime);
        result = 31 * result + Arrays.hashCode(imageBytes);
        return result;
    }

    @Override
    public String toString() {
        return "PassportData{"
                + "documentNumber='" + documentNumber + '\''
                + ", dateOfBirth='" + dateOfBirth + '\''
                + ", dateOfExpiry='" + dateOfExpiry + '\''
                + ", mrz='" + mrz + '\''
                + ", fullName='" + fullName + '\''
                + ", nationality='" + nationality + '\''
                + ", imageMime='" + imageMime + '\''
                + ", imageBytes=" + (imageBytes == null ? "null" : ("byte[" + imageBytes.length + "]"))
                + '}';
    }
}
