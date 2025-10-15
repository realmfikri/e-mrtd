package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import emu.PersonalizationSupport.SODArtifacts;

import net.sf.scuba.data.Gender;

final class TestCardManager {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

  static final String DEFAULT_DOC = "123456789";
  static final String DEFAULT_DOB = "750101";
  static final String DEFAULT_DOE = "250101";

  private TestCardManager() {
  }

  static TestCard provisionCard() throws Exception {
    return provisionCard(false);
  }

  static TestCard provisionCard(boolean tamperDg1) throws Exception {
    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short) 0, (byte) MRTD_AID.length);
    simulator.installApplet(aid, sos.passportapplet.PassportApplet.class);

    CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();

    selectApplet(channel);

    MRZInfo mrz = new MRZInfo(
        "P<",
        "UTO",
        "BEAN",
        "HAPPY",
        DEFAULT_DOC,
        "UTO",
        DEFAULT_DOB,
        Gender.MALE,
        DEFAULT_DOE,
        "");
    DG1File dg1 = new DG1File(mrz);
    byte[] dg1Bytes = dg1.getEncoded();

    int[] tagList = new int[]{
        LDSFile.EF_DG1_TAG,
        LDSFile.EF_DG2_TAG,
        LDSFile.EF_DG3_TAG,
        LDSFile.EF_DG4_TAG,
        LDSFile.EF_DG14_TAG,
        LDSFile.EF_DG15_TAG
    };
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();

    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(dg1Bytes, 480, 600, false);

    createEF(channel, PassportService.EF_COM, comBytes.length);
    selectEF(channel, PassportService.EF_COM);
    writeBinary(channel, comBytes);

    createEF(channel, PassportService.EF_DG1, dg1Bytes.length);
    selectEF(channel, PassportService.EF_DG1);
    writeBinary(channel, dg1Bytes);

    if (artifacts.cardAccessBytes != null && artifacts.cardAccessBytes.length > 0) {
      createEF(channel, PassportService.EF_CARD_ACCESS, artifacts.cardAccessBytes.length);
      selectEF(channel, PassportService.EF_CARD_ACCESS);
      writeBinary(channel, artifacts.cardAccessBytes);
    }

    createEF(channel, PassportService.EF_DG2, artifacts.dg2Bytes.length);
    selectEF(channel, PassportService.EF_DG2);
    writeBinary(channel, artifacts.dg2Bytes);

    if (artifacts.dg3Bytes != null && artifacts.dg3Bytes.length > 0) {
      createEF(channel, PassportService.EF_DG3, artifacts.dg3Bytes.length);
      selectEF(channel, PassportService.EF_DG3);
      writeBinary(channel, artifacts.dg3Bytes);
    }

    if (artifacts.dg4Bytes != null && artifacts.dg4Bytes.length > 0) {
      createEF(channel, PassportService.EF_DG4, artifacts.dg4Bytes.length);
      selectEF(channel, PassportService.EF_DG4);
      writeBinary(channel, artifacts.dg4Bytes);
    }

    if (artifacts.dg14Bytes != null && artifacts.dg14Bytes.length > 0) {
      createEF(channel, PassportService.EF_DG14, artifacts.dg14Bytes.length);
      selectEF(channel, PassportService.EF_DG14);
      writeBinary(channel, artifacts.dg14Bytes);
    }

    createEF(channel, PassportService.EF_DG15, artifacts.dg15Bytes.length);
    selectEF(channel, PassportService.EF_DG15);
    writeBinary(channel, artifacts.dg15Bytes);

    createEF(channel, PassportService.EF_SOD, artifacts.sodBytes.length);
    selectEF(channel, PassportService.EF_SOD);
    writeBinary(channel, artifacts.sodBytes);

    if (tamperDg1) {
      byte[] mutated = Arrays.copyOf(dg1Bytes, dg1Bytes.length);
      mutated[0] ^= 0xFF;
      selectEF(channel, PassportService.EF_DG1);
      writeBinary(channel, mutated);
    }

    byte[] mrzSeed = buildMrzSeed(DEFAULT_DOC, DEFAULT_DOB, DEFAULT_DOE);
    putData(channel, 0x00, 0x62, mrzSeed);
    seedActiveAuthenticationKey(channel, artifacts.docSignerKeyPair.getPrivate());

    card.disconnect(false);

    TerminalCardService terminalService = new TerminalCardService(terminal);
    terminalService.open();

    LoggingCardService loggingService = new LoggingCardService(terminalService);
    loggingService.open();

    PassportService passportService = new PassportService(
        loggingService,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false,
        false);
    passportService.open();
    passportService.sendSelectApplet(false);

    BACKey bacKey = new BACKey(DEFAULT_DOC, DEFAULT_DOB, DEFAULT_DOE);

    return new TestCard(simulator, terminal, terminalService, loggingService, passportService, artifacts, bacKey, dg1Bytes);
  }

  private static void selectApplet(CardChannel channel) throws javax.smartcardio.CardException {
    byte[] command = new byte[5 + MRTD_AID.length];
    command[0] = 0x00;
    command[1] = (byte) 0xA4;
    command[2] = 0x04;
    command[3] = 0x0C;
    command[4] = (byte) MRTD_AID.length;
    System.arraycopy(MRTD_AID, 0, command, 5, MRTD_AID.length);
    ResponseAPDU response = channel.transmit(new CommandAPDU(command));
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException("SELECT AID failed: SW=" + Integer.toHexString(response.getSW()));
    }
  }

  private static void createEF(CardChannel channel, short fid, int size) throws Exception {
    byte[] fcp = new byte[]{
        (byte) 0x63, 0x04,
        (byte) ((size >> 8) & 0xFF), (byte) (size & 0xFF),
        (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)
    };
    transmit(channel, 0x00, 0xE0, 0x00, 0x00, fcp);
  }

  private static void selectEF(CardChannel channel, short fid) throws Exception {
    byte[] cmd = new byte[]{0x00, (byte) 0xA4, 0x02, 0x0C, 0x02, (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)};
    transmit(channel, cmd);
  }

  private static void writeBinary(CardChannel channel, byte[] data) throws Exception {
    int offset = 0;
    while (offset < data.length) {
      int len = Math.min(0xFF, data.length - offset);
      byte[] chunk = Arrays.copyOfRange(data, offset, offset + len);
      transmit(channel, 0x00, 0xD6, (offset >> 8) & 0xFF, offset & 0xFF, chunk);
      offset += len;
    }
  }

  private static void putData(CardChannel channel, int p1, int p2, byte[] data) throws Exception {
    ResponseAPDU response = channel.transmit(new CommandAPDU(0x00, 0xDA, p1, p2, data));
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(String.format(
          "PUT DATA %02X %02X failed: SW=%04X",
          p1 & 0xFF, p2 & 0xFF, response.getSW()));
    }
  }

  private static void transmit(CardChannel channel, int cla, int ins, int p1, int p2, byte[] data) throws Exception {
    ResponseAPDU response = channel.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(String.format(
          "APDU %02X %02X %02X %02X failed: SW=%04X",
          cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF, response.getSW()));
    }
  }

  private static void transmit(CardChannel channel, byte[] data) throws Exception {
    ResponseAPDU response = channel.transmit(new CommandAPDU(data));
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException("APDU failed: SW=" + Integer.toHexString(response.getSW()));
    }
  }

  private static byte[] buildMrzSeed(String doc, String dob, String doe) {
    byte[] docBytes = doc.getBytes(StandardCharsets.US_ASCII);
    byte[] dobBytes = dob.getBytes(StandardCharsets.US_ASCII);
    byte[] doeBytes = doe.getBytes(StandardCharsets.US_ASCII);

    ByteArrayOutputStream inner = new ByteArrayOutputStream();
    writeTag(inner, 0x5F1F);
    writeLength(inner, docBytes.length);
    inner.write(docBytes, 0, docBytes.length);

    writeTag(inner, 0x5F18);
    writeLength(inner, dobBytes.length);
    inner.write(dobBytes, 0, dobBytes.length);

    writeTag(inner, 0x5F19);
    writeLength(inner, doeBytes.length);
    inner.write(doeBytes, 0, doeBytes.length);

    byte[] innerBytes = inner.toByteArray();
    ByteArrayOutputStream outer = new ByteArrayOutputStream();
    outer.write(0x62);
    writeLength(outer, innerBytes.length);
    outer.write(innerBytes, 0, innerBytes.length);
    return outer.toByteArray();
  }

  private static void seedActiveAuthenticationKey(CardChannel channel, PrivateKey privateKey) throws Exception {
    if (!(privateKey instanceof RSAPrivateKey)) {
      return;
    }
    RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
    byte[] modulus = stripLeadingZero(rsaKey.getModulus().toByteArray());
    byte[] exponent = stripLeadingZero(rsaKey.getPrivateExponent().toByteArray());

    putData(channel, 0x00, 0x60, buildRsaPrivateKeyTlv(0x60, modulus));
    putData(channel, 0x00, 0x61, buildRsaPrivateKeyTlv(0x61, exponent));
  }

  private static byte[] buildRsaPrivateKeyTlv(int containerTag, byte[] keyBytes) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTag(out, containerTag);
    writeLength(out, 0);
    writeTag(out, 0x04);
    writeLength(out, keyBytes.length);
    out.write(keyBytes, 0, keyBytes.length);
    return out.toByteArray();
  }

  private static byte[] stripLeadingZero(byte[] input) {
    if (input.length <= 1 || input[0] != 0x00) {
      return input;
    }
    int index = 0;
    while (index < input.length - 1 && input[index] == 0x00) {
      index++;
    }
    return Arrays.copyOfRange(input, index, input.length);
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

  static final class TestCard {
    final CardSimulator simulator;
    final CardTerminal terminal;
    final TerminalCardService terminalService;
    final LoggingCardService loggingService;
    final PassportService passportService;
    final SODArtifacts artifacts;
    final BACKey bacKey;
    final byte[] dg1Bytes;

    TestCard(CardSimulator simulator,
             CardTerminal terminal,
             TerminalCardService terminalService,
             LoggingCardService loggingService,
             PassportService passportService,
             SODArtifacts artifacts,
             BACKey bacKey,
             byte[] dg1Bytes) {
      this.simulator = simulator;
      this.terminal = terminal;
      this.terminalService = terminalService;
      this.loggingService = loggingService;
      this.passportService = passportService;
      this.artifacts = artifacts;
      this.bacKey = bacKey;
      this.dg1Bytes = dg1Bytes;
    }

    void close() {
      try {
        passportService.close();
      } catch (Exception ignore) {
      }
      try {
        loggingService.close();
      } catch (Exception ignore) {
      }
      try {
        terminalService.close();
      } catch (Exception ignore) {
      }
    }
  }
}
