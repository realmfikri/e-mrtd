package com.example;

import java.util.Arrays;

public record PassportData(
        String documentNumber,
        String dateOfBirth,    // YYMMDD
        String dateOfExpiry,   // YYMMDD
        String mrz,            // teks MRZ (DG1) bisa null
        String fullName,       // "PRIMARY SECONDARY" dari MRZ
        String nationality,    // kode negara 3 huruf
        String imageMime,      // mime foto (jpeg/jp2/wsq) bisa null
        byte[] imageBytes      // foto (boleh null)
) {
    public boolean isValid() { return mrz != null && !mrz.isBlank(); }

    // alias biar kompatibel sama UI lama (opsional)
    public String getNama() { return fullName; }
    public String getNik()  { return documentNumber; }
    public String getTtl()  { return dateOfBirth; }

    public byte[] safeImageBytes() {
        return imageBytes == null ? null : Arrays.copyOf(imageBytes, imageBytes.length);
    }
}

