package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

import org.jmrtd.PassportService;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.COMFile;
import net.sf.scuba.data.Gender;
import org.jmrtd.lds.icao.MRZInfo;

import emu.PersonalizationSupport.SODArtifacts;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class PersoMain {
  // AID MRTD (ICAO 9303)
  private static final byte[] MRTD_AID = new byte[]{(byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01};

  // FID standar
  private static final short EF_COM = (short)0x011E;
  private static final short EF_DG1 = (short)0x0101;
  private static final short EF_DG2 = (short)0x0102;
  private static final short EF_DG3 = (short)0x0103;
  private static final short EF_DG4 = (short)0x0104;
  private static final short EF_DG14 = PassportService.EF_DG14;
  private static final short EF_DG15 = (short)0x010F;
  private static final short EF_SOD = (short)0x011D;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  public static void main(String[] args) throws Exception {
    boolean corruptDG2 = false;
    boolean largeDG2 = false;
    for (String arg : args) {
      if ("--corrupt-dg2".equals(arg)) {
        corruptDG2 = true;
      } else if ("--large-dg2".equals(arg)) {
        largeDG2 = true;
      }
    }

    // 1) Boot simulator + install applet
    CardSimulator sim = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);
    sim.installApplet(aid, sos.passportapplet.PassportApplet.class);
    CardTerminal term = CardTerminalSimulator.terminal(sim);
    Card card = term.connect("*");
    CardChannel ch = card.getBasicChannel();

    // 2) SELECT AID
    apdu(ch, 0x00, 0xA4, 0x04, 0x0C, MRTD_AID, "SELECT AID");

    // 3) Siapkan payload LDS (COM + DG1) dengan JMRTD
    // DG1 dari MRZ dummy
    //  P<UTO BEAN<<HAPPY, no dok 123456789, WN UTO, Lahir 75-01-01, Exp 25-01-01, gender M
    MRZInfo mrz = new MRZInfo("P<", "UTO", "BEAN", "HAPPY",
            "123456789", "UTO", "750101", Gender.MALE, "250101", "");
    int faceWidth = largeDG2 ? 720 : 480;
    int faceHeight = largeDG2 ? 960 : 600;
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .withFaceSyntheticSize(faceWidth, faceHeight)
        .corruptDg2(corruptDG2)
        .build();

    int[] tagList = job.getComTagList().stream().mapToInt(Integer::intValue).toArray();
    COMFile com = new COMFile("1.7", "4.0.0", tagList); // versi umum; cukup untuk uji
    byte[] comBytes = com.getEncoded();
    byte[] dg1Bytes = job.getDg1Bytes();

    // 4) Tulis EF.COM (CREATE FILE + SELECT + UPDATE BINARY)
    createEF(ch, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEF(ch, EF_COM, "SELECT EF.COM before WRITE");
    writeBinary(ch, comBytes, "WRITE EF.COM");

    // 5) Tulis EF.DG1 (CREATE FILE + SELECT + UPDATE BINARY)
    createEF(ch, EF_DG1, dg1Bytes.length, "CREATE EF.DG1");
    selectEF(ch, EF_DG1, "SELECT EF.DG1 before WRITE");
    writeBinary(ch, dg1Bytes, "WRITE EF.DG1");

    // 6) Buat EF.DG2, EF.SOD, EF.DG15 dan tulis
    SODArtifacts sodArtifacts = PersonalizationSupport.buildArtifacts(job);
    System.out.printf("Synthetic biometrics → DG3=%d bytes, DG4=%d bytes.%n",
        sodArtifacts.getDg3Bytes() != null ? sodArtifacts.getDg3Bytes().length : 0,
        sodArtifacts.getDg4Bytes() != null ? sodArtifacts.getDg4Bytes().length : 0);

    byte[] cardAccessBytes = sodArtifacts.getCardAccessBytes();
    if (cardAccessBytes != null && cardAccessBytes.length > 0) {
      createEF(ch, EF_CARD_ACCESS, cardAccessBytes.length, "CREATE EF.CardAccess");
      selectEF(ch, EF_CARD_ACCESS, "SELECT EF.CardAccess before WRITE");
      writeBinary(ch, cardAccessBytes, "WRITE EF.CardAccess");
    }

    byte[] dg2Bytes = sodArtifacts.getDg2Bytes();
    createEF(ch, EF_DG2, dg2Bytes.length, "CREATE EF.DG2");
    selectEF(ch, EF_DG2, "SELECT EF.DG2 before WRITE");
    writeBinary(ch, dg2Bytes, "WRITE EF.DG2");

    byte[] dg3Bytes = sodArtifacts.getDg3Bytes();
    if (dg3Bytes != null && dg3Bytes.length > 0) {
      createEF(ch, EF_DG3, dg3Bytes.length, "CREATE EF.DG3");
      selectEF(ch, EF_DG3, "SELECT EF.DG3 before WRITE");
      writeBinary(ch, dg3Bytes, "WRITE EF.DG3");
    }

    byte[] dg4Bytes = sodArtifacts.getDg4Bytes();
    if (dg4Bytes != null && dg4Bytes.length > 0) {
      createEF(ch, EF_DG4, dg4Bytes.length, "CREATE EF.DG4");
      selectEF(ch, EF_DG4, "SELECT EF.DG4 before WRITE");
      writeBinary(ch, dg4Bytes, "WRITE EF.DG4");
    }

    byte[] dg14Bytes = sodArtifacts.getDg14Bytes();
    if (dg14Bytes != null && dg14Bytes.length > 0) {
      createEF(ch, EF_DG14, dg14Bytes.length, "CREATE EF.DG14");
      selectEF(ch, EF_DG14, "SELECT EF.DG14 before WRITE");
      writeBinary(ch, dg14Bytes, "WRITE EF.DG14");
    }

    byte[] dg15Bytes = sodArtifacts.getDg15Bytes();
    createEF(ch, EF_DG15, dg15Bytes.length, "CREATE EF.DG15");
    selectEF(ch, EF_DG15, "SELECT EF.DG15 before WRITE");
    writeBinary(ch, dg15Bytes, "WRITE EF.DG15");
    byte[] sodBytes = sodArtifacts.getSodBytes();
    createEF(ch, EF_SOD, sodBytes.length, "CREATE EF.SOD");
    selectEF(ch, EF_SOD, "SELECT EF.SOD before WRITE");
    writeBinary(ch, sodBytes, "WRITE EF.SOD");

    // 7) Simpan trust store untuk Passive Authentication verifier
    Path trustDir = Paths.get("target", "trust-store");
    Files.createDirectories(trustDir);
    try (var stream = Files.list(trustDir)) {
      stream.filter(Files::isRegularFile).forEach(path -> {
        try {
          Files.delete(path);
        } catch (Exception ignore) {
        }
      });
    }
    Files.deleteIfExists(trustDir.resolve("dsc.cer"));
    Files.write(trustDir.resolve("csca.cer"), sodArtifacts.getCscaCert().getEncoded());
    System.out.println("Trust store updated -> " + trustDir.toAbsolutePath());

//     // 1) Read full EF.DG1
// selectEF(ch, EF_DG1, "SELECT EF.DG1 (full read)");
// byte[] back = new byte[dg1Bytes.length];
// int got = 0;
// while (got < back.length) {
//   int chunk = Math.min(0xFF, back.length - got);
//   ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, 0xB0, (got >> 8) & 0xFF, got & 0xFF, chunk));
//   System.arraycopy(r.getData(), 0, back, got, r.getData().length);
//   got += r.getData().length;
// }

// // 2) Bandingkan byte-by-byte
// System.out.println("DG1 bytes equal? " + java.util.Arrays.equals(dg1Bytes, back));

// // 3) Decode & print MRZ dari apa yang CHIP kasih balik
// org.jmrtd.lds.icao.DG1File dg1Check = new org.jmrtd.lds.icao.DG1File(new java.io.ByteArrayInputStream(back));
// org.jmrtd.lds.icao.MRZInfo info = dg1Check.getMRZInfo();
// System.out.println("MRZ >> " + info.getPrimaryIdentifier() + "," + info.getSecondaryIdentifier()
//   + " #" + info.getDocumentNumber() + " DOB=" + info.getDateOfBirth() + " DOE=" + info.getDateOfExpiry());


    // 6) Verifikasi cepat: SELECT + READ sebagian header file
    // (opsional; hanya ngecek SW & panjang)
    selectEF(ch, EF_COM, "SELECT EF.COM (verify)");
    readSome(ch, Math.min(16, comBytes.length), "READ EF.COM head");

    selectEF(ch, EF_DG1, "SELECT EF.DG1 (verify)");
    readSome(ch, Math.min(16, dg1Bytes.length), "READ EF.DG1 head");

    System.out.println("\n✅ Personalisasi selesai: EF.COM, EF.DG1, EF.SOD ditulis.");
  }

  // ======= util APDU =======

  /** CREATE FILE seperti pola JMRTD: 00 E0 00 00 Lc | 63 04 <sizeHi sizeLo fidHi fidLo> */
  private static void createEF(CardChannel ch, short fid, int size, String label) throws Exception {
    byte[] fcp = new byte[]{
      (byte)0x63, 0x04,
      (byte)((size >> 8) & 0xFF), (byte)(size & 0xFF),
      (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)
    };
    apdu(ch, 0x00, 0xE0, 0x00, 0x00, fcp, label);
  }

  private static void writeBinary(CardChannel ch, byte[] data, String label) throws Exception {
    // chunk <= 255
    int off = 0;
    while (off < data.length) {
      int len = Math.min(0xFF, data.length - off);
      byte[] chunk = Arrays.copyOfRange(data, off, off + len);
      apdu(ch, 0x00, 0xD6, (off >> 8) & 0xFF, off & 0xFF, chunk,
           label + " (ofs=" + off + ", len=" + len + ")");
      off += len;
    }
  }


  private static void selectEF(CardChannel ch, short fid, String label) throws Exception {
    byte[] sfid = new byte[]{0x02, (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)};
    // 00 A4 02 0C 02 <FID>
    byte[] cmd = new byte[]{0x00, (byte)0xA4, 0x02, 0x0C, 0x02, sfid[1], sfid[2]};
    ResponseAPDU r = ch.transmit(new CommandAPDU(cmd));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
  }

  private static void readSome(CardChannel ch, int le, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, le));
    System.out.printf("%s → SW=%04X len=%d%n", label, r.getSW(), r.getData().length);
  }

  private static ResponseAPDU apdu(CardChannel ch, int cla, int ins, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
    return r;
  }
}
