package emu;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

/** Utility helpers for encoding key material into TLV containers expected by the applet. */
final class KeyEncodingUtil {

  private KeyEncodingUtil() {
  }

  static byte[] buildEcPrivateKeyTlv(ECPrivateKey privateKey, ECPublicKey publicKey) {
    ECParameterSpec params = privateKey.getParams();
    if (params == null && publicKey != null) {
      params = publicKey.getParams();
    }
    if (params == null) {
      throw new IllegalArgumentException("EC key is missing domain parameters");
    }
    EllipticCurve curve = params.getCurve();
    int fieldLength = (curve.getField().getFieldSize() + 7) / 8;
    int orderLength = (params.getOrder().bitLength() + 7) / 8;

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeEcFieldDescriptor(out, curve.getField(), fieldLength);
    writeEcParameter(out, 0x82, toUnsigned(curve.getA(), fieldLength));
    writeEcParameter(out, 0x83, toUnsigned(curve.getB(), fieldLength));
    writeEcParameter(out, 0x84, encodeEcPoint(params.getGenerator(), fieldLength));
    writeEcParameter(out, 0x85, toUnsigned(params.getOrder(), orderLength));
    writeEcParameter(out, 0x86, toUnsigned(privateKey.getS(), orderLength));
    int cofactor = params.getCofactor();
    if (cofactor > 0) {
      writeEcParameter(out, 0x87, toUnsigned(BigInteger.valueOf(cofactor), -1));
    }
    return out.toByteArray();
  }

  static byte[] buildRsaPrivateKeyTlv(int containerTag, byte[] keyBytes) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTag(out, containerTag);
    // The applet expects the outer container length to be zero and treats the nested
    // OCTET STRING as a sibling TLV (legacy PUT DATA layout).
    writeLength(out, 0);
    writeTag(out, 0x04);
    writeLength(out, keyBytes.length);
    out.write(keyBytes, 0, keyBytes.length);
    return out.toByteArray();
  }

  static byte[] stripLeadingZero(byte[] input) {
    if (input.length <= 1 || input[0] != 0x00) {
      return input;
    }
    int index = 0;
    while (index < input.length - 1 && input[index] == 0x00) {
      index++;
    }
    return Arrays.copyOfRange(input, index, input.length);
  }

  private static byte[] encodeEcPoint(ECPoint point, int fieldLength) {
    byte[] x = toUnsigned(point.getAffineX(), fieldLength);
    byte[] y = toUnsigned(point.getAffineY(), fieldLength);
    ByteArrayOutputStream encoded = new ByteArrayOutputStream(1 + x.length + y.length);
    encoded.write(0x04);
    encoded.write(x, 0, x.length);
    encoded.write(y, 0, y.length);
    return encoded.toByteArray();
  }

  private static void writeEcFieldDescriptor(ByteArrayOutputStream out, ECField field, int fieldLength) {
    byte[] value;
    if (field instanceof ECFieldFp) {
      ECFieldFp fp = (ECFieldFp) field;
      value = toUnsigned(fp.getP(), fieldLength);
    } else if (field instanceof ECFieldF2m) {
      ECFieldF2m f2m = (ECFieldF2m) field;
      int[] midTerms = f2m.getMidTermsOfReductionPolynomial();
      if (midTerms == null || midTerms.length == 0) {
        throw new IllegalArgumentException("Binary field is missing reduction polynomial terms");
      }
      ByteArrayOutputStream fieldBytes = new ByteArrayOutputStream();
      if (midTerms.length == 1) {
        writeShort(fieldBytes, (short) midTerms[0]);
      } else if (midTerms.length == 3) {
        for (int term : midTerms) {
          writeShort(fieldBytes, (short) term);
        }
      } else {
        throw new IllegalArgumentException("Unsupported binary field configuration");
      }
      value = fieldBytes.toByteArray();
    } else {
      throw new IllegalArgumentException("Unsupported EC field: " + field.getClass());
    }
    writeEcParameter(out, 0x81, value);
  }

  private static void writeEcParameter(ByteArrayOutputStream out, int tag, byte[] value) {
    if (value == null) {
      throw new IllegalArgumentException("EC parameter value is required");
    }
    writeTag(out, tag);
    writeLength(out, value.length);
    out.write(value, 0, value.length);
  }

  private static void writeShort(ByteArrayOutputStream out, short value) {
    out.write((value >> 8) & 0xFF);
    out.write(value & 0xFF);
  }

  private static byte[] toUnsigned(BigInteger value, int targetLength) {
    if (value == null) {
      throw new IllegalArgumentException("Value must not be null");
    }
    byte[] raw = value.toByteArray();
    if (raw.length > 1 && raw[0] == 0x00) {
      raw = Arrays.copyOfRange(raw, 1, raw.length);
    }
    if (targetLength > 0) {
      if (raw.length > targetLength) {
        throw new IllegalArgumentException("Value exceeds requested length");
      }
      if (raw.length == targetLength) {
        return raw;
      }
      byte[] padded = new byte[targetLength];
      System.arraycopy(raw, 0, padded, targetLength - raw.length, raw.length);
      return padded;
    }
    return raw;
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
