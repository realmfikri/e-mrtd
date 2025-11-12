package com.example;

import emu.reader.PassportData;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.PassportService;
import org.jmrtd.BACKey;
import org.jmrtd.AccessKeySpec;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
// OPSIONAL: kalau mau pakai konstanta MIME di lain waktu boleh keep ini
import org.jmrtd.lds.ImageInfo;

// ✅ import yang benar untuk DG2 (ISO 19794)
import org.jmrtd.lds.iso19794.FaceInfo;          // FIX: needed
import org.jmrtd.lds.iso19794.FaceImageInfo;     // FIX: needed

import java.security.Security;

public class UniversalPassportReader {

    /** CLI launcher: wrapper ke API readPassport(...) */
    public static void main(String[] args) {
        String documentNumber = args.length > 0 ? args[0] : "X5215910<";
        String dateOfBirth    = args.length > 1 ? args[1] : "030804";
        String dateOfExpiry   = args.length > 2 ? args[2] : "300224";

        try {
            PassportData p = readPassport(documentNumber, dateOfBirth, dateOfExpiry);
            System.out.println("=== eMRTD Read Result ===");
            System.out.println("Valid      : " + (p.mrz() != null && !p.mrz().isBlank()));
            System.out.println("Doc Number : " + p.documentNumber());
            System.out.println("Full Name  : " + p.fullName());
            System.out.println("Nationality: " + p.nationality());
            System.out.println("DOB        : " + p.dateOfBirth());
            System.out.println("Expiry     : " + p.dateOfExpiry());
            System.out.println("MRZ length : " + (p.mrz() == null ? 0 : p.mrz().length()));
            System.out.println("Image MIME : " + p.imageMime());
            System.out.println("Image size : " + (p.imageBytes() == null ? 0 : p.imageBytes().length) + " bytes");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /** API buat UI — end-to-end baca paspor */
    public static PassportData readPassport(String documentNumber,
                                            String dateOfBirth,
                                            String dateOfExpiry) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals == null || terminals.isEmpty()) {
            throw new IllegalStateException("No NFC terminal found.");
        }

        CardTerminal terminal = terminals.get(0);
        terminal.waitForCardPresent(0);

        CardService cardService = new TerminalCardService(terminal);
        cardService.open();

        PassportService service = new PassportService(cardService, 256, 224, false, false);
        service.open();
        service.sendSelectApplet(false);

        try {
            AccessKeySpec bacKey = new BACKey(documentNumber, dateOfBirth, dateOfExpiry);
            service.doBAC(bacKey);
            service.sendSelectApplet(true);

            // === DG1 (MRZ) ===
            MRZInfo mrzInfo;
            String mrzText;
            try (InputStream dg1In = service.getInputStream(PassportService.EF_DG1)) {
                DG1File dg1File = new DG1File(dg1In);
                mrzInfo = dg1File.getMRZInfo();
                mrzText = (mrzInfo == null) ? null : mrzInfo.toString();
            }

            String fullName = "";
            String nationality = "";
            if (mrzInfo != null) {
                String primary = nz(mrzInfo.getPrimaryIdentifier());
                String secondary = nz(mrzInfo.getSecondaryIdentifier());
                fullName = (primary + " " + secondary).trim().replaceAll(" +", " ");
                nationality = nz(mrzInfo.getNationality());
            }

            // === DG2 (foto) — optional ===
            byte[] imageBytes = null;
            String imageMime = null;
            try (InputStream dg2In = service.getInputStream(PassportService.EF_DG2)) {
                DG2File dg2File = new DG2File(dg2In);

                // FIX: pakai tipe FaceInfo/FaceImageInfo
                if (!dg2File.getFaceInfos().isEmpty()) {
                    FaceInfo face = dg2File.getFaceInfos().get(0);               // FIX
                    if (!face.getFaceImageInfos().isEmpty()) {
                        FaceImageInfo fii = face.getFaceImageInfos().get(0);     // FIX
                        imageMime = fii.getMimeType();
                        try (InputStream imgIn = fii.getImageInputStream();
                             ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                            byte[] tmp = new byte[4096];
                            int read;
                            while ((read = imgIn.read(tmp)) != -1) {
                                buffer.write(tmp, 0, read);
                            }
                            imageBytes = buffer.toByteArray();
                        }
                    }
                }
            } catch (Exception ignored) {
                // DG2 optional
            }

            return new PassportData(
                    documentNumber,
                    dateOfBirth,
                    dateOfExpiry,
                    mrzText,
                    fullName,
                    nationality,
                    imageMime,
                    imageBytes
            );
        } finally {
            try { service.close(); } catch (Exception ignored) {}
            try { cardService.close(); } catch (Exception ignored) {}
        }
    }

    private static String nz(String s) { return s == null ? "" : s; }
}

