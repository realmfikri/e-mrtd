package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

import net.sf.scuba.smartcards.TerminalCardService;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import net.sf.scuba.data.Gender;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ReadDG1Main {
  private static final byte[] MRTD_AID = new byte[]{(byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01};
  private static final short EF_COM = (short)0x011E;
  private static final short EF_DG1 = (short)0x0101;

  // >>> samakan MRZ ini dengan yang kamu tulis ke EF.DG1 saat "PersoMain"
  private static final String DOC = "123456789";
  private static final String DOB = "750101";
  private static final String DOE = "250101";

  public static void main(String[] args) throws Exception {
    boolean seed = Arrays.asList(args).contains("--seed");

    // Boot emulator & install applet
    CardSimulator sim = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);
    sim.installApplet(aid, sos.passportapplet.PassportApplet.class);

    CardTerminal term = CardTerminalSimulator.terminal(sim);
    Card card = term.connect("*");
    CardChannel ch = card.getBasicChannel();

    // SELECT AID
    apdu(ch, 0x00, 0xA4, 0x04, 0x0C, MRTD_AID, "SELECT AID");

    // --- tulis data minimal (COM + DG1) ke chip ---
    personalize(ch);

    // --- langkah penting: tanam kunci BAC di applet ---
    if (seed) {
      byte[] mrzSeed = buildMrzSeed(DOC, DOB, DOE);
      boolean ok = putData(ch, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
      if (!ok) throw new RuntimeException("SET BAC via PUT DATA gagal. Cek format TLV.");
    }

    // --- sekarang baca via PassportService + BAC ---
    PassportService svc = new PassportService(
        new TerminalCardService(term),
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false, false);
    svc.open();
    svc.sendSelectApplet(false);

    // lakukan BAC (host derivasi dari MRZ di atas)
    svc.doBAC(new BACKey(DOC, DOB, DOE));

    // baca DG1 (MRZ)
    try (InputStream in = svc.getInputStream(PassportService.EF_DG1)) {
      DG1File dg1 = new DG1File(in);
      MRZInfo info = dg1.getMRZInfo();
      System.out.println("==== DG1 ====");
      System.out.println("Doc#: " + info.getDocumentNumber());
      System.out.println("DOB  : " + info.getDateOfBirth());
      System.out.println("DOE  : " + info.getDateOfExpiry());
      System.out.println("Name : " + info.getSecondaryIdentifier() + ", " + info.getPrimaryIdentifier());
      System.out.println("Gender: " + info.getGender()); // jmrtd 0.8.x
    }
  }

  private static void personalize(CardChannel ch) throws Exception {
    int[] tagList = new int[]{LDSFile.EF_DG1_TAG};
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();

    MRZInfo mrz = new MRZInfo("P<", "UTO", "BEAN", "HAPPY",
        DOC, "UTO", DOB, Gender.MALE, DOE, "");
    DG1File dg1 = new DG1File(mrz);
    byte[] dg1Bytes = dg1.getEncoded();

    createEF(ch, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEF(ch, EF_COM, "SELECT EF.COM before WRITE");
    writeBinary(ch, comBytes, "WRITE EF.COM");

    createEF(ch, EF_DG1, dg1Bytes.length, "CREATE EF.DG1");
    selectEF(ch, EF_DG1, "SELECT EF.DG1 before WRITE");
    writeBinary(ch, dg1Bytes, "WRITE EF.DG1");
  }

  private static boolean putData(CardChannel ch, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, 0xDA, p1, p2, data)); // ISO7816 PUT DATA
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    return r.getSW() == 0x9000;
  }

  private static ResponseAPDU apdu(CardChannel ch, int cla, int ins, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
    return r;
  }

  private static void createEF(CardChannel ch, short fid, int size, String label) throws Exception {
    byte[] fcp = new byte[]{
        (byte)0x63, 0x04,
        (byte)((size >> 8) & 0xFF), (byte)(size & 0xFF),
        (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)
    };
    apdu(ch, 0x00, 0xE0, 0x00, 0x00, fcp, label);
  }

  private static void selectEF(CardChannel ch, short fid, String label) throws Exception {
    byte[] cmd = new byte[]{0x00, (byte)0xA4, 0x02, 0x0C, 0x02, (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)};
    ResponseAPDU r = ch.transmit(new CommandAPDU(cmd));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
  }

  private static void writeBinary(CardChannel ch, byte[] data, String label) throws Exception {
    int off = 0;
    while (off < data.length) {
      int len = Math.min(0xFF, data.length - off);
      byte[] chunk = Arrays.copyOfRange(data, off, off + len);
      apdu(ch, 0x00, 0xD6, (off >> 8) & 0xFF, off & 0xFF, chunk,
          label + " (ofs=" + off + ", len=" + len + ")");
      off += len;
    }
  }

  private static byte[] buildMrzSeed(String doc, String dob, String doe) {
    byte[] docBytes = doc.getBytes(StandardCharsets.US_ASCII);
    byte[] dobBytes = dob.getBytes(StandardCharsets.US_ASCII);
    byte[] doeBytes = doe.getBytes(StandardCharsets.US_ASCII);

    ByteArrayOutputStream inner = new ByteArrayOutputStream();
    writeTag(inner, 0x5F1F); // Document number
    writeLength(inner, docBytes.length);
    inner.write(docBytes, 0, docBytes.length);

    writeTag(inner, 0x5F18); // Date of birth
    writeLength(inner, dobBytes.length);
    inner.write(dobBytes, 0, dobBytes.length);

    writeTag(inner, 0x5F19); // Date of expiry
    writeLength(inner, doeBytes.length);
    inner.write(doeBytes, 0, doeBytes.length);

    byte[] innerBytes = inner.toByteArray();
    ByteArrayOutputStream outer = new ByteArrayOutputStream();
    outer.write(0x62); // MRZ_TAG
    writeLength(outer, innerBytes.length);
    outer.write(innerBytes, 0, innerBytes.length);

    return outer.toByteArray();
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
      // simple long-form length support (not expected here but keeps it correct)
      int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
      out.write(0x80 | numBytes);
      for (int i = numBytes - 1; i >= 0; i--) {
        out.write((length >> (8 * i)) & 0xFF);
      }
    }
  }
}
