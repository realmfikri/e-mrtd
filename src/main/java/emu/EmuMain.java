package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

public class EmuMain {
  // AID MRTD (ICAO 9303): A0 00 00 02 47 10 01
  private static final byte[] MRTD_AID = new byte[]{
      (byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01
  };

  public static void main(String[] args) throws Exception {
    CardSimulator sim = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);

    // Kelas harus "sos.passportapplet.PassportApplet" sesuai package di source
    sim.installApplet(aid, sos.passportapplet.PassportApplet.class);

    // Buat terminal virtual dan konek
    CardTerminal term = CardTerminalSimulator.terminal(sim);
    Card card = term.connect("*"); // atau "T=1"
    CardChannel ch = card.getBasicChannel();

    // SELECT AID: 00 A4 04 0C Lc AID...
    byte[] select = new byte[5 + MRTD_AID.length];
    select[0] = 0x00; select[1] = (byte)0xA4; select[2] = 0x04; select[3] = 0x0C;
    select[4] = (byte)MRTD_AID.length;
    System.arraycopy(MRTD_AID, 0, select, 5, MRTD_AID.length);

    ResponseAPDU r = ch.transmit(new CommandAPDU(select));
    System.out.printf("SELECT SW=%04X%n", r.getSW());
  }
}
