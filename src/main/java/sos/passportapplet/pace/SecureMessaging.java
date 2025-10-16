package sos.passportapplet.pace;

import javacard.framework.APDU;

import javax.crypto.SecretKey;

/**
 * Common operations required by the simulator's secure messaging helpers.
 */
public interface SecureMessaging {

  void setKeys(SecretKey macKey, SecretKey encKey);

  short unwrapCommand(byte[] ssc, APDU apdu);

  short wrapResponse(byte[] ssc, APDU apdu, short plaintextOffset, short plaintextLen, short sw1sw2);

  short getApduBufferOffset(short plaintextLength);

  int getBlockSize();
}
