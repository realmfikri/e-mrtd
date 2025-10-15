package emu;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

/**
 * Simple decorator that prints APDU traffic to stdout.
 */
final class LoggingCardService extends CardService {

  private final CardService delegate;

  LoggingCardService(CardService delegate) {
    this.delegate = delegate;
  }

  @Override
  public void open() throws CardServiceException {
    delegate.open();
  }

  @Override
  public boolean isOpen() {
    return delegate.isOpen();
  }

  @Override
  public void close() {
    delegate.close();
  }

  @Override
  public boolean isConnectionLost(Exception e) {
    try {
      return delegate.isConnectionLost(e);
    } catch (AbstractMethodError error) {
      // Older CardService implementations (like TerminalCardService from the
      // version bundled with net.sf.scuba) don't provide the newer
      // isConnectionLost hook. Fall back to the pre-hook behaviour, which is to
      // treat all exceptions as non-fatal and let callers decide.
      return false;
    }
  }

  @Override
  public byte[] getATR() throws CardServiceException {
    return delegate.getATR();
  }

  @Override
  public ResponseAPDU transmit(CommandAPDU apdu) throws CardServiceException {
    boolean protectedApdu = isSecureMessaging(apdu.getCLA());
    System.out.printf("-> CLA=%02X INS=%02X P1=%02X P2=%02X Lc=%d Le=%d%s%n",
        apdu.getCLA() & 0xFF,
        apdu.getINS() & 0xFF,
        apdu.getP1() & 0xFF,
        apdu.getP2() & 0xFF,
        apdu.getNc(),
        apdu.getNe(),
        protectedApdu ? " [SM]" : "");
    ResponseAPDU response = delegate.transmit(apdu);
    System.out.printf("<- SW=%04X dataLen=%d%s%n",
        response.getSW(),
        response.getData().length,
        protectedApdu ? " [protected]" : "");
    return response;
  }

  private static boolean isSecureMessaging(int cla) {
    int smBits = cla & 0x0C;
    return smBits == 0x0C;
  }

  @Override
  public String toString() {
    return "LoggingCardService(" + delegate + ")";
  }
}
