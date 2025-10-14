package sos.passportapplet.pace;

import java.util.Arrays;

/**
 * Simple container for PACE passwords keyed by reference id.
 *
 * Key references follow ICAO 9303 / BSI TR-03110 assignments:
 * 1 = MRZ, 2 = CAN, 3 = PIN, 4 = PUK.
 */
public final class PaceSecrets {

  public static final byte KEY_REF_MRZ = 1;
  public static final byte KEY_REF_CAN = 2;
  public static final byte KEY_REF_PIN = 3;
  public static final byte KEY_REF_PUK = 4;

  private final byte[][] secrets;

  public PaceSecrets() {
    this.secrets = new byte[5][];
  }

  public void clear() {
    for (byte[] secret : secrets) {
      if (secret != null) {
        Arrays.fill(secret, (byte) 0);
      }
    }
    Arrays.fill(secrets, null);
  }

  public void setSecret(byte keyReference, byte[] data, int offset, int length) {
    if (!isSupportedKeyReference(keyReference)) {
      throw new IllegalArgumentException("Unsupported PACE key reference: " + keyReference);
    }
    byte[] copy = new byte[length];
    System.arraycopy(data, offset, copy, 0, length);
    secrets[keyReference] = copy;
  }

  public byte[] getSecret(byte keyReference) {
    if (!isSupportedKeyReference(keyReference)) {
      return null;
    }
    return secrets[keyReference];
  }

  public boolean hasSecret(byte keyReference) {
    byte[] secret = getSecret(keyReference);
    return secret != null && secret.length > 0;
  }

  private static boolean isSupportedKeyReference(byte keyReference) {
    return keyReference >= KEY_REF_MRZ && keyReference <= KEY_REF_PUK;
  }
}
