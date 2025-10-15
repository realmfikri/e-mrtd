package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Module9LifecycleTest {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

  @Test
  void lifecycleTransitionsEnforcePolicies() throws Exception {
    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short) 0, (byte) MRTD_AID.length);
    simulator.installApplet(aid, sos.passportapplet.PassportApplet.class);

    CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();

    selectApplet(channel);

    ResponseAPDU prematureLock = channel.transmit(new CommandAPDU(0x00, 0xDA, 0xDE, 0xAD, new byte[0]));
    assertEquals(0x6985, prematureLock.getSW(), "LOCKED state must be unreachable before personalization");

    ResponseAPDU personalize = channel.transmit(new CommandAPDU(0x00, 0xDA, 0xDE, 0xAF, new byte[0]));
    assertEquals(0x9000, personalize.getSW(), "Transition to PERSONALIZED must succeed from PREP");

    ResponseAPDU personalizeAgain = channel.transmit(new CommandAPDU(0x00, 0xDA, 0xDE, 0xAF, new byte[0]));
    assertEquals(0x9000, personalizeAgain.getSW(), "Repeated PERSONALIZED command must be idempotent");

    byte[] mrzSeed = buildMrzSeed("123456789", "750101", "250101");
    ResponseAPDU mrzAfterPersonalize = channel.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0x62, mrzSeed));
    assertEquals(0x6986, mrzAfterPersonalize.getSW(), "MRZ PUT DATA must be blocked after personalization");

    ResponseAPDU lock = channel.transmit(new CommandAPDU(0x00, 0xDA, 0xDE, 0xAD, new byte[0]));
    assertEquals(0x9000, lock.getSW(), "Transition to LOCKED must succeed from PERSONALIZED");

    ResponseAPDU mrzAfterLock = channel.transmit(new CommandAPDU(0x00, 0xDA, 0x00, 0x62, mrzSeed));
    assertEquals(0x6985, mrzAfterLock.getSW(), "MRZ PUT DATA must be blocked in LOCKED state");

    byte[] fcp = new byte[]{(byte) 0x63, 0x04, 0x00, 0x20, 0x7F, 0x01};
    ResponseAPDU createAfterLock = channel.transmit(new CommandAPDU(0x00, 0xE0, 0x00, 0x00, fcp));
    assertEquals(0x6985, createAfterLock.getSW(), "CREATE FILE must be denied once the chip is locked");

    card.disconnect(false);
  }

  private static void selectApplet(CardChannel channel) throws Exception {
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

  private static byte[] buildMrzSeed(String doc, String dob, String doe) throws Exception {
    // Reuse TestCardManager encoding for MRZ TLV
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
}
