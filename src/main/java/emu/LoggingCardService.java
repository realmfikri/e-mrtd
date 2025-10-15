package emu;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

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
    System.out.printf("-> %s (%02X %02X %02X %02X Lc=%d)\n",
        Hex.bytesToHexString(apdu.getBytes()),
        apdu.getCLA() & 0xFF,
        apdu.getINS() & 0xFF,
        apdu.getP1() & 0xFF,
        apdu.getP2() & 0xFF,
        apdu.getNc());
    ResponseAPDU response = delegate.transmit(apdu);
    System.out.printf("<- %s SW=%04X\n",
        response.getData().length > 0 ? Hex.bytesToHexString(response.getData()) : "",
        response.getSW());
    return response;
  }

  @Override
  public String toString() {
    return "LoggingCardService(" + delegate + ")";
  }
}
