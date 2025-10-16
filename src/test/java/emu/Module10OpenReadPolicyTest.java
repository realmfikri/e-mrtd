package emu;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.jmrtd.PassportService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Module10OpenReadPolicyTest {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

  @Test
  void defaultLockedPolicyRequiresSecureMessaging() throws Exception {
    TestCardManager.TestCard card = TestCardManager.provisionCard();
    try {
      Card connection = card.terminal.connect("*");
      try {
        CardChannel channel = connection.getBasicChannel();
        selectApplet(channel);

        assertEquals(0x9000, selectFile(channel, PassportService.EF_COM).getSW());
        ResponseAPDU readCom = channel.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 0x01));
        assertEquals(0x6982, readCom.getSW(), "EF.COM must require secure messaging by default");

        assertEquals(0x9000, selectFile(channel, PassportService.EF_SOD).getSW());
        ResponseAPDU readSod = channel.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 0x01));
        assertEquals(0x6982, readSod.getSW(), "EF.SOD must require secure messaging by default");
      } finally {
        connection.disconnect(false);
      }
    } finally {
      card.close();
    }
  }

  @Test
  void developerToggleAllowsOpenComAndSodReads() throws Exception {
    TestCardManager.TestCard card = TestCardManager.provisionCard(false, true);
    try {
      Card connection = card.terminal.connect("*");
      try {
        CardChannel channel = connection.getBasicChannel();
        selectApplet(channel);

        assertEquals(0x9000, selectFile(channel, PassportService.EF_COM).getSW());
        ResponseAPDU readCom = channel.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 0x04));
        assertEquals(0x9000, readCom.getSW(), "EF.COM must be readable in the clear when enabled");
        assertTrue(readCom.getData().length > 0, "EF.COM must return data when open reads are enabled");

        assertEquals(0x9000, selectFile(channel, PassportService.EF_SOD).getSW());
        ResponseAPDU readSod = channel.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 0x04));
        assertEquals(0x9000, readSod.getSW(), "EF.SOD must be readable in the clear when enabled");
        assertTrue(readSod.getData().length > 0, "EF.SOD must return data when open reads are enabled");
      } finally {
        connection.disconnect(false);
      }
    } finally {
      card.close();
    }
  }

  private static void selectApplet(CardChannel channel) throws CardException {
    CommandAPDU select = new CommandAPDU(0x00, 0xA4, 0x04, 0x0C, MRTD_AID);
    ResponseAPDU response = channel.transmit(select);
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException("SELECT AID failed: SW=" + Integer.toHexString(response.getSW()));
    }
  }

  private static ResponseAPDU selectFile(CardChannel channel, short fid) throws CardException {
    byte[] data = new byte[]{(byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)};
    CommandAPDU command = new CommandAPDU(0x00, 0xA4, 0x02, 0x0C, data);
    return channel.transmit(command);
  }
}
