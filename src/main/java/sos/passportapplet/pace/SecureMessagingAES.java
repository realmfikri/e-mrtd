package sos.passportapplet.pace;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * AES/CBC + AES-CMAC secure messaging utilities for the PACE profile.
 *
 * <p>This helper mirrors the structure defined in ICAO Doc 9303,
 * Part 11, Annex E. It is only used in the simulator (jCardSim)
 * and therefore leverages the JCE APIs.</p>
 */
public final class SecureMessagingAES {

  private static final int BLOCK_SIZE = 16;
  private static final int MAC_LENGTH = 8;

  private final Cipher cipher;
  private final Cipher ivCipher;
  private final Mac mac;
  private SecretKey macKey;
  private SecretKey encKey;

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public SecureMessagingAES() {
    try {
      cipher = Cipher.getInstance("AES/CBC/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      ivCipher = Cipher.getInstance("AES/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to initialise AES secure messaging primitives", e);
    }
  }

  public void setKeys(SecretKey macKey, SecretKey encKey) {
    this.macKey = macKey;
    this.encKey = encKey;
  }

  public short unwrapCommand(byte[] ssc, APDU apdu) {
    ensureKeys();

    byte[] buf = apdu.getBuffer();
    byte cla = buf[ISO7816.OFFSET_CLA];
    byte ins = buf[ISO7816.OFFSET_INS];
    byte p1 = buf[ISO7816.OFFSET_P1];
    byte p2 = buf[ISO7816.OFFSET_P2];
    short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);

    apdu.setIncomingAndReceive();
    incrementSSC(ssc);

    short cursor = ISO7816.OFFSET_CDATA;
    short remaining = lc;

    short do87Offset = -1;
    short do87Length = 0;
    short do87ValueOffset = -1;
    short do97Offset = -1;
    short do97Length = 0;
    short macValueOffset = -1;
    short macLength = 0;

    while (remaining > 0) {
      short tagOffset = cursor;
      byte tag = buf[cursor++];
      remaining--;

      short[] offsetRef = new short[]{cursor};
      short length = readLength(buf, offsetRef);
      short lengthBytes = (short) (offsetRef[0] - cursor);
      cursor = offsetRef[0];
      remaining -= (short) (lengthBytes + length);

      short valueOffset = cursor;
      cursor += length;

      switch (tag) {
        case (byte) 0x87:
          do87Offset = tagOffset;
          do87Length = (short) (cursor - tagOffset);
          do87ValueOffset = valueOffset;
          if (length < 1 || buf[valueOffset] != (byte) 0x01) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
          }
          break;
        case (byte) 0x97:
          do97Offset = tagOffset;
          do97Length = (short) (cursor - tagOffset);
          break;
        case (byte) 0x8E:
          macValueOffset = valueOffset;
          macLength = length;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }

    if (macValueOffset < 0 || macLength <= 0) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (macLength != MAC_LENGTH && macLength != BLOCK_SIZE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    byte[] header = new byte[]{(byte) (cla | 0x0C), ins, p1, p2};
    byte[] paddedHeader = padIso(header);

    ByteArrayOutputStream macStream = new ByteArrayOutputStream();
    macStream.write(ssc, 0, ssc.length);
    macStream.write(paddedHeader, 0, paddedHeader.length);
    if (do87Offset >= 0) {
      macStream.write(buf, do87Offset, do87Length);
    }
    if (do97Offset >= 0) {
      macStream.write(buf, do97Offset, do97Length);
    }
    byte[] macInput = padIso(macStream.toByteArray());

    byte[] expectedMac = computeMac(macInput);
    for (int i = 0; i < macLength; i++) {
      if (buf[macValueOffset + i] != expectedMac[i]) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    }

    short plaintextLc = 0;
    if (do87Offset >= 0) {
      short ciphertextOffset = (short) (do87ValueOffset + 1);
      short ciphertextLength = (short) (do87Length - (ciphertextOffset - do87Offset));
      byte[] iv = deriveIv(ssc);
      byte[] plaintextPadded = decrypt(buf, ciphertextOffset, ciphertextLength, iv);
      plaintextLc = calcUnpaddedLength(plaintextPadded);
      System.arraycopy(plaintextPadded, 0, buf, ISO7816.OFFSET_CDATA, plaintextLc);
      buf[ISO7816.OFFSET_LC] = (byte) (plaintextLc & 0xFF);
    } else {
      buf[ISO7816.OFFSET_LC] = 0;
    }

    short le = 0;
    if (do97Offset >= 0) {
      short valueOffset = findValueOffset(buf, do97Offset);
      short valueLength = (short) (do97Offset + do97Length - valueOffset);
      le = decodeLe(buf, valueOffset, valueLength);
    }

    // wipe trailing bytes so that remaining TLVs do not leak into subsequent processing
    short wipeOffset = (short) (ISO7816.OFFSET_CDATA + plaintextLc);
    short wipeLength = (short) (lc - plaintextLc);
    if (wipeLength > 0) {
      Util.arrayFillNonAtomic(buf, wipeOffset, wipeLength, (byte) 0x00);
    }

    return le;
  }

  public short wrapResponse(byte[] ssc, APDU apdu, short plaintextOffset, short plaintextLen, short sw1sw2) {
    ensureKeys();

    byte[] buf = apdu.getBuffer();
    byte[] responsePlaintext = new byte[plaintextLen];
    if (plaintextLen > 0) {
      System.arraycopy(buf, plaintextOffset, responsePlaintext, 0, plaintextLen);
    }

    incrementSSC(ssc);

    byte[] do87 = null;
    if (plaintextLen > 0) {
      byte[] padded = padIso(responsePlaintext);
      byte[] iv = deriveIv(ssc);
      byte[] ciphertext = encrypt(padded, iv);
      ByteArrayOutputStream do87Stream = new ByteArrayOutputStream();
      do87Stream.write((byte) 0x87);
      writeLength(do87Stream, ciphertext.length + 1);
      do87Stream.write(0x01);
      do87Stream.write(ciphertext, 0, ciphertext.length);
      do87 = do87Stream.toByteArray();
    }

    byte[] do99 = new byte[]{
        (byte) 0x99,
        0x02,
        (byte) ((sw1sw2 >> 8) & 0xFF),
        (byte) (sw1sw2 & 0xFF)
    };

    ByteArrayOutputStream macStream = new ByteArrayOutputStream();
    macStream.write(ssc, 0, ssc.length);
    if (do87 != null) {
      macStream.write(do87, 0, do87.length);
    }
    macStream.write(do99, 0, do99.length);
    byte[] macInput = padIso(macStream.toByteArray());

    byte[] macBytesFull = computeMac(macInput);
    byte[] macTruncated = Arrays.copyOf(macBytesFull, MAC_LENGTH);

    byte[] do8e = new byte[2 + MAC_LENGTH];
    do8e[0] = (byte) 0x8E;
    do8e[1] = (byte) MAC_LENGTH;
    System.arraycopy(macTruncated, 0, do8e, 2, MAC_LENGTH);

    int offset = 0;
    if (do87 != null) {
      System.arraycopy(do87, 0, buf, offset, do87.length);
      offset += do87.length;
    }
    System.arraycopy(do99, 0, buf, offset, do99.length);
    offset += do99.length;
    System.arraycopy(do8e, 0, buf, offset, do8e.length);
    offset += do8e.length;

    return (short) offset;
  }

  public short getApduBufferOffset(short plaintextLength) {
    short do87Bytes = 2;
    short do87DataLen = (short) (lengthWithPadding(plaintextLength) + 1);

    if (do87DataLen < 0x80) {
      do87Bytes++;
    } else if (do87DataLen <= 0xFF) {
      do87Bytes += 2;
    } else {
      do87Bytes += (short) (plaintextLength > 0xFF ? 2 : 1);
    }
    return do87Bytes;
  }

  private void ensureKeys() {
    if (macKey == null || encKey == null) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  private static short readLength(byte[] buf, short[] offsetRef) {
    short cursor = offsetRef[0];
    int first = buf[cursor++] & 0xFF;
    int length;
    if ((first & 0x80) == 0) {
      length = first;
    } else {
      int count = first & 0x7F;
      length = 0;
      for (int i = 0; i < count; i++) {
        length = (length << 8) | (buf[cursor++] & 0xFF);
      }
    }
    offsetRef[0] = cursor;
    return (short) length;
  }

  private static short findValueOffset(byte[] buf, short tagOffset) {
    short[] offsetRef = new short[]{(short) (tagOffset + 1)};
    readLength(buf, offsetRef);
    return offsetRef[0];
  }

  private short decodeLe(byte[] buf, short offset, short length) {
    int value = 0;
    for (int i = 0; i < length; i++) {
      value = (value << 8) | (buf[offset + i] & 0xFF);
    }
    return (short) value;
  }

  private byte[] computeMac(byte[] input) {
    try {
      mac.init(macKey);
      return mac.doFinal(input);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Failed to compute AES CMAC", e);
    }
  }

  private byte[] encrypt(byte[] paddedPlaintext, byte[] iv) {
    try {
      cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));
      return cipher.doFinal(paddedPlaintext);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("AES encrypt failed", e);
    }
  }

  private byte[] decrypt(byte[] buf, short offset, short length, byte[] iv) {
    try {
      cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));
      return cipher.doFinal(buf, offset, length);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("AES decrypt failed", e);
    }
  }

  private static byte[] padIso(byte[] data) {
    int len = data.length;
    int padLen = BLOCK_SIZE - (len % BLOCK_SIZE);
    if (padLen == 0) {
      padLen = BLOCK_SIZE;
    }
    byte[] padded = Arrays.copyOf(data, len + padLen);
    padded[len] = (byte) 0x80;
    return padded;
  }

  private short calcUnpaddedLength(byte[] padded) {
    for (int i = padded.length - 1; i >= 0; i--) {
      if (padded[i] == (byte) 0x80) {
        return (short) i;
      }
      if (padded[i] != 0) {
        return (short) padded.length;
      }
    }
    return 0;
  }

  private void writeLength(ByteArrayOutputStream out, int length) {
    if (length < 0x80) {
      out.write(length);
    } else {
      int numBytes = 0;
      int tmp = length;
      while (tmp > 0) {
        numBytes++;
        tmp >>= 8;
      }
      out.write(0x80 | numBytes);
      for (int i = numBytes - 1; i >= 0; i--) {
        out.write((length >> (i * 8)) & 0xFF);
      }
    }
  }

  private byte[] deriveIv(byte[] ssc) {
    try {
      ivCipher.init(Cipher.ENCRYPT_MODE, encKey);
      return ivCipher.doFinal(ssc);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Failed to derive PACE IV", e);
    }
  }

  private static void incrementSSC(byte[] ssc) {
    for (int i = ssc.length - 1; i >= 0; i--) {
      int value = (ssc[i] & 0xFF) + 1;
      ssc[i] = (byte) value;
      if ((value & 0x100) == 0) {
        break;
      }
    }
  }

  private static short lengthWithPadding(short inputLength) {
    int blocks = (inputLength + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (blocks == 0) {
      blocks = 1;
    }
    return (short) (blocks * BLOCK_SIZE);
  }
}
