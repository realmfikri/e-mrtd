package sos.passportapplet.pace;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.jmrtd.lds.PACEInfo;

/**
 * Runtime PACE session context, tracking selection, derived keys and state.
 */
public final class PaceContext {

  public enum Step {
    NONE,
    NONCE_SENT,
    MAPPED,
    KEY_AGREED,
    TOKENS_VERIFIED
  }

  private String protocolOid;
  private AlgorithmParameterSpec parameterSpec;
  private BigInteger keyId;
  private byte keyReference;
  private Step step;
  private byte[] nonceS;
  private KeyPair chipEphemeralKeyPair;
  private PublicKey terminalPublicKey;
  private byte[] sharedSecret;
  private SecretKey staticKey;
  private SecretKey sessionEncKey;
  private SecretKey sessionMacKey;
  private byte[] sendSequenceCounter;
  private PACEInfo.MappingType mappingType;
  private String agreementAlgorithm;
  private String cipherAlgorithm;
  private String digestAlgorithm;
  private int keyLength;
  private AlgorithmParameterSpec ephemeralParameterSpec;
  private KeyPair mappingKeyPair;
  private byte[] paceSendSequenceCounter;

  public PaceContext() {
    reset();
  }

  public void reset() {
    protocolOid = null;
    parameterSpec = null;
    keyId = null;
    keyReference = 0;
    step = Step.NONE;
    nonceS = null;
    chipEphemeralKeyPair = null;
    terminalPublicKey = null;
    sharedSecret = null;
    staticKey = null;
    sessionEncKey = null;
    sessionMacKey = null;
    if (sendSequenceCounter != null) {
      Arrays.fill(sendSequenceCounter, (byte) 0);
    }
    sendSequenceCounter = null;
    mappingType = null;
    agreementAlgorithm = null;
    cipherAlgorithm = null;
    digestAlgorithm = null;
    keyLength = 0;
    ephemeralParameterSpec = null;
    mappingKeyPair = null;
    if (paceSendSequenceCounter != null) {
      Arrays.fill(paceSendSequenceCounter, (byte) 0);
    }
    paceSendSequenceCounter = null;
  }

  public String getProtocolOid() {
    return protocolOid;
  }

  public void setProtocolOid(String protocolOid) {
    this.protocolOid = protocolOid;
  }

  public AlgorithmParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  public void setParameterSpec(AlgorithmParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
  }

  public BigInteger getKeyId() {
    return keyId;
  }

  public void setKeyId(BigInteger keyId) {
    this.keyId = keyId;
  }

  public byte getKeyReference() {
    return keyReference;
  }

  public void setKeyReference(byte keyReference) {
    this.keyReference = keyReference;
  }

  public Step getStep() {
    return step;
  }

  public void setStep(Step step) {
    this.step = step;
  }

  public byte[] getNonceS() {
    return nonceS;
  }

  public void setNonceS(byte[] nonceS) {
    this.nonceS = nonceS;
  }

  public KeyPair getChipEphemeralKeyPair() {
    return chipEphemeralKeyPair;
  }

  public void setChipEphemeralKeyPair(KeyPair chipEphemeralKeyPair) {
    this.chipEphemeralKeyPair = chipEphemeralKeyPair;
  }

  public PublicKey getTerminalPublicKey() {
    return terminalPublicKey;
  }

  public void setTerminalPublicKey(PublicKey terminalPublicKey) {
    this.terminalPublicKey = terminalPublicKey;
  }

  public byte[] getSharedSecret() {
    return sharedSecret;
  }

  public void setSharedSecret(byte[] sharedSecret) {
    this.sharedSecret = sharedSecret;
  }

  public SecretKey getStaticKey() {
    return staticKey;
  }

  public void setStaticKey(SecretKey staticKey) {
    this.staticKey = staticKey;
  }

  public SecretKey getSessionEncKey() {
    return sessionEncKey;
  }

  public void setSessionEncKey(SecretKey sessionEncKey) {
    this.sessionEncKey = sessionEncKey;
  }

  public SecretKey getSessionMacKey() {
    return sessionMacKey;
  }

  public void setSessionMacKey(SecretKey sessionMacKey) {
    this.sessionMacKey = sessionMacKey;
  }

  public byte[] getSendSequenceCounter() {
    return sendSequenceCounter;
  }

  public void setSendSequenceCounter(byte[] sendSequenceCounter) {
    this.sendSequenceCounter = sendSequenceCounter;
  }

  public PACEInfo.MappingType getMappingType() {
    return mappingType;
  }

  public void setMappingType(PACEInfo.MappingType mappingType) {
    this.mappingType = mappingType;
  }

  public String getAgreementAlgorithm() {
    return agreementAlgorithm;
  }

  public void setAgreementAlgorithm(String agreementAlgorithm) {
    this.agreementAlgorithm = agreementAlgorithm;
  }

  public String getCipherAlgorithm() {
    return cipherAlgorithm;
  }

  public void setCipherAlgorithm(String cipherAlgorithm) {
    this.cipherAlgorithm = cipherAlgorithm;
  }

  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(String digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

  public AlgorithmParameterSpec getEphemeralParameterSpec() {
    return ephemeralParameterSpec;
  }

  public void setEphemeralParameterSpec(AlgorithmParameterSpec ephemeralParameterSpec) {
    this.ephemeralParameterSpec = ephemeralParameterSpec;
  }

  public KeyPair getMappingKeyPair() {
    return mappingKeyPair;
  }

  public void setMappingKeyPair(KeyPair mappingKeyPair) {
    this.mappingKeyPair = mappingKeyPair;
  }

  public byte[] getPaceSendSequenceCounter() {
    return paceSendSequenceCounter;
  }

  public void setPaceSendSequenceCounter(byte[] paceSendSequenceCounter) {
    this.paceSendSequenceCounter = paceSendSequenceCounter;
  }
}
