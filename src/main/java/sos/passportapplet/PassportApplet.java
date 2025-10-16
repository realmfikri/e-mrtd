/*
 * passportapplet - A reference implementation of the MRTD standards.
 *
 * Copyright (C) 2006  SoS group, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: PassportApplet.java 945 2009-05-12 08:31:57Z woj76 $
 */

package sos.passportapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Arrays;
import java.util.function.Function;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKey;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.PACEInfo.MappingType;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.protocol.PACEProtocol;

import sos.passportapplet.pace.PaceContext;
import sos.passportapplet.pace.PaceSecrets;
import sos.passportapplet.pace.SecureMessaging;
import sos.passportapplet.pace.SecureMessagingAES;
import sos.passportapplet.pace.SecureMessagingDES;

// API for setATRHistBytes - requires Global Platform API gp211.jar
// Comment out the following line if API not available.
// import org.globalplatform.GPSystem;

/**
 * PassportApplet
 * 
 * @author ceesb (ceeesb@gmail.com)
 * @author woj (woj@cs.ru.nl)
 * @author martijno (martijn.oostdijk@gmail.com)
 * 
 * @version $Revision: 945 $
 */
public class PassportApplet extends Applet implements ISO7816 {
    static byte volatileState[];

    static byte persistentState;

    /* values for volatile state */
    static final byte CHALLENGED = 1;

    static final byte MUTUAL_AUTHENTICATED = 2; // ie BAC

    static final byte FILE_SELECTED = 4;

    static final byte CHIP_AUTHENTICATED = 0x10;

    static final byte TERMINAL_AUTHENTICATED = 0x20;

    static final byte PACE_ESTABLISHED = 0x40;

    /* values for persistent state */
    static final byte HAS_MUTUALAUTHENTICATION_KEYS = 1;

    static final byte HAS_EXPONENT = 2;
    private static final byte ALLOW_OPEN_COM_SOD_READS = 0x04;

    private static final byte LIFECYCLE_STATE_MASK = (byte) 0xC0;

    private static final byte LIFECYCLE_PREPERSONALIZED = 0x00;

    private static final byte LIFECYCLE_PERSONALIZED = 0x40;

    private static final byte LIFECYCLE_LOCKED = (byte) 0x80;

    static final byte HAS_MODULUS = 8;

    static final byte HAS_EC_KEY = 0x10;

    static final byte HAS_CVCERTIFICATE = 0x20;

    static final byte CHAIN_CLA = 0x10;

    /* for authentication */
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    static final byte INS_GET_CHALLENGE = (byte) 0x84;

    static final byte CLA_PROTECTED_APDU = 0x0c;

    static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    static final byte INS_GENERAL_AUTHENTICATE = (byte) 0x86;

    /* for EAC */
    static final byte INS_PSO = (byte) 0x2A;

    static final byte INS_MSE = (byte) 0x22;

    static final byte P2_VERIFYCERT = (byte) 0xBE;

    static final byte P1_SETFORCOMPUTATION = (byte) 0x41;

    static final byte P1_SETFORVERIFICATION = (byte) 0x81;

    static final byte P2_KAT = (byte) 0xA6;

    static final byte P2_DST = (byte) 0xB6;

    static final byte P2_AT = (byte) 0xA4;

    /* for reading */
    static final byte INS_SELECT_FILE = (byte) 0xA4;

    static final byte INS_READ_BINARY = (byte) 0xB0;

    /* for writing */
    static final byte INS_UPDATE_BINARY = (byte) 0xd6;

    static final byte INS_CREATE_FILE = (byte) 0xe0;

    static final byte INS_PUT_DATA = (byte) 0xda;

    static final short KEY_LENGTH = 16;

    static final short KEYMATERIAL_LENGTH = 16;

    static final short RND_LENGTH = 8;

    static final short MAC_LENGTH = 8;

    private static final byte PRIVMODULUS_TAG = 0x60;

    private static final byte PRIVEXPONENT_TAG = 0x61;

    private static final byte MRZ_TAG = 0x62;

    private static final byte PACE_SECRET_CONTAINER_TAG = 0x65;

    private static final byte PACE_SECRET_ENTRY_TAG = 0x66;
    private static final byte CURRENT_DATE_TAG = 0x67;

    private static final byte ECPRIVATEKEY_TAG = 0x63;

    private static final byte CVCERTIFICATE_TAG = 0x64;

    /* status words */
    private static final short SW_OK = (short) 0x9000;

    private static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;

    static final short SW_INTERNAL_ERROR = (short) 0x6d66;

    private byte[] rnd;

    private byte[] ssc;
    private byte[] smExpectedSSC;
    private byte[] paceSSC;
    private byte[] paceExpectedSSC;

    private byte[] documentNumber;

    private FileSystem fileSystem;

    private RandomData randomData;

    private short selectedFile;

    private PassportCrypto crypto;

    private PassportInit init;

    static CVCertificate certificate;

    KeyStore keyStore;

    private byte[] lastINS;

    private short[] chainingOffset;

    private byte[] chainingTmp;

    private String paceDocumentNumber;
    private String paceDateOfBirth;
    private String paceDateOfExpiry;

    private final sos.passportapplet.pace.PaceSecrets paceSecrets;

    private final sos.passportapplet.pace.PaceContext paceContext;

    private final SecureMessagingAES paceSecureMessagingAes;
    private final SecureMessagingDES paceSecureMessagingDes;
    private SecureMessaging paceSecureMessaging;
    private String chipAuthProtocolOid;
    private BigInteger chipAuthKeyId;
    private String chipAuthCipherAlgorithm;
    private int chipAuthKeyLength;

    private PACEInfo[] cachedPaceInfos;

    // This is as long we suspect a card verifiable certifcate could be
    private static final short CHAINING_BUFFER_LENGTH = 400;

    // public ATRGlobal atrGlobal;

    /**
     * Creates a new passport applet.
     */
    public PassportApplet(byte mode) {

        fileSystem = new FileSystem();

        persistentState = 0;
        setLifecycleState(LIFECYCLE_PREPERSONALIZED);

        randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);

        certificate = new CVCertificate();

        keyStore = new KeyStore(mode);
        switch (mode) {
        case PassportCrypto.CREF_MODE:
            crypto = new CREFPassportCrypto(keyStore);
            break;
        case PassportCrypto.PERFECTWORLD_MODE:
            crypto = new PassportCrypto(keyStore);
            break;
        case PassportCrypto.JCOP41_MODE:
            crypto = new JCOP41PassportCrypto(keyStore);
            break;
        }
        init = new PassportInit(crypto);

        rnd = JCSystem.makeTransientByteArray(RND_LENGTH,
                JCSystem.CLEAR_ON_RESET);
        ssc = JCSystem
                .makeTransientByteArray((byte) 8, JCSystem.CLEAR_ON_RESET);
        smExpectedSSC = JCSystem
                .makeTransientByteArray((byte) 8, JCSystem.CLEAR_ON_RESET);
        paceSSC = new byte[16];
        paceExpectedSSC = new byte[16];
        volatileState = JCSystem.makeTransientByteArray((byte) 1,
                JCSystem.CLEAR_ON_RESET);
        lastINS = JCSystem.makeTransientByteArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        chainingOffset = JCSystem.makeTransientShortArray((short) 1,
                JCSystem.CLEAR_ON_DESELECT);
        chainingTmp = JCSystem.makeTransientByteArray(CHAINING_BUFFER_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);

        paceSecrets = new PaceSecrets();
        paceContext = new PaceContext();
        paceSecureMessagingAes = new SecureMessagingAES();
        paceSecureMessagingDes = new SecureMessagingDES();
        paceSecureMessaging = paceSecureMessagingAes;
    }

    /**
     * Installs an instance of the applet. The default crypto mode is now
     * PERFECTWORLD_MODE as the new JCOP41 cards support all required crypto.
     * 
     * @param buffer
     * @param offset
     * @param length
     * @see javacard.framework.Applet#install(byte[], byte, byte)
     */
    public static void install(byte[] buffer, short offset, byte length) {
        (new PassportApplet(PassportCrypto.JCOP41_MODE)).register();
    }

    /**
     * Processes incoming APDUs.
     * 
     * @param apdu
     * @see javacard.framework.Applet#process(javacard.framework.APDU)
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];
        short sw1sw2 = SW_OK;
        boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        boolean usingPaceSm = hasPaceEstablished();
        short responseLength = 0;
        short le = 0;

        if (lastINS[0] != ins) {
            chainingOffset[0] = 0;
        }
        lastINS[0] = ins;

        /* Ignore APDU that selects this applet... */
        if (selectingApplet()) {
            // Set ATR Historical Bytes (ATS).
            // Requires gp211 API. Comment out the following line if API not
            // available.
            // org.globalplatform.GPSystem.setATRHistBytes(ATRGlobal.ATR_HIST,
            // (short) 0x00, ATRGlobal.ATR_HIST_LEN);
            return;
        }

        if (protectedApdu) {
            if (hasMutuallyAuthenticated()) {
                try {
                    assertSecureMessagingCounter();
                    le = crypto.unwrapCommandAPDU(ssc, apdu);
                    updateSmExpectedCounter();
                } catch (CardRuntimeException e) {
                    updateSmExpectedCounter();
                    sw1sw2 = normalizeSmError(e.getReason());
                }
            } else if (usingPaceSm) {
                try {
                    assertPaceSecureMessagingCounter();
                    le = paceSecureMessaging.unwrapCommand(paceContext.getPaceSendSequenceCounter(), apdu);
                    updatePaceExpectedCounter();
                } catch (CardRuntimeException e) {
                    updatePaceExpectedCounter();
                    sw1sw2 = normalizeSmError(e.getReason());
                }
            } else {
                ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            }
        }

        if (sw1sw2 == SW_OK) {
            try {
                enforceSecureMessaging(ins, protectedApdu);
                responseLength = processAPDU(apdu, cla, ins, protectedApdu, le);
            } catch (CardRuntimeException e) {
                sw1sw2 = e.getReason();
            }
        }

        if (protectedApdu) {
            if (hasMutuallyAuthenticated()) {
                responseLength = crypto.wrapResponseAPDU(ssc, apdu, crypto
                        .getApduBufferOffset(responseLength), responseLength,
                        sw1sw2);
                updateSmExpectedCounter();
            } else if (usingPaceSm) {
                short offset = paceSecureMessaging.getApduBufferOffset(responseLength);
                responseLength = paceSecureMessaging.wrapResponse(paceContext.getPaceSendSequenceCounter(), apdu,
                        offset, responseLength, sw1sw2);
                updatePaceExpectedCounter();
            }
        }

        if (responseLength > 0) {
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING)
                apdu.setOutgoing();
            if (apdu.getCurrentState() != APDU.STATE_OUTGOING_LENGTH_KNOWN)
                apdu.setOutgoingLength(responseLength);
            apdu.sendBytes((short) 0, responseLength);
        }

        if (sw1sw2 != SW_OK) {
            ISOException.throwIt(sw1sw2);
        }
    }

    /**
     * Processes incoming APDUs, excluding Secure Messaging.
     *
     * This method assumes SM protection has been removed from the
     * incoming APDU, and does not add SM protection to the response.
     * Handling of Secure Messaging is done in process(APDU apdu)
     *
     * @param protectedApdu true if Secure Messaging is used
     * @return length of the response APDU
     */
    public short processAPDU(APDU apdu, byte cla, byte ins,
            boolean protectedApdu, short le) {
        short responseLength = 0;
        byte[] buffer = apdu.getBuffer();

        switch (ins) {
        case INS_GET_CHALLENGE:
            responseLength = processGetChallenge(apdu, protectedApdu, le);
            break;
        case INS_EXTERNAL_AUTHENTICATE:
            responseLength = processMutualAuthenticate(apdu, protectedApdu);
            break;
        case INS_PSO:
            if (!protectedApdu) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            responseLength = processPSO(apdu);
            break;
        case INS_MSE:
            boolean paceMse = (buffer[OFFSET_P1] == (byte) 0xC1 && buffer[OFFSET_P2] == (byte) 0xA4);
            if (!protectedApdu && !paceMse) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            responseLength = processMSE(apdu);
            break;
        case INS_GENERAL_AUTHENTICATE:
            responseLength = processGeneralAuthenticate(apdu, protectedApdu);
            break;
        case INS_INTERNAL_AUTHENTICATE:
            responseLength = processInternalAuthenticate(apdu, protectedApdu);
            break;
        case INS_SELECT_FILE:
            processSelectFile(apdu);
            break;
        case INS_READ_BINARY:
            responseLength = processReadBinary(apdu, le, protectedApdu);
            break;
        case INS_UPDATE_BINARY:
            processUpdateBinary(apdu);
            break;
        case INS_CREATE_FILE:
            processCreateFile(apdu);
            break;
        case INS_PUT_DATA:
            processPutData(apdu);
            break;
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            break;
        }
        return responseLength;
    }

    private void enforceSecureMessaging(byte ins, boolean protectedApdu) {
        if (!hasSecureMessagingSession()) {
            return;
        }
        if (!protectedApdu && requiresSecureMessaging(ins)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private boolean requiresSecureMessaging(byte ins) {
        switch (ins) {
        case INS_SELECT_FILE:
        case INS_READ_BINARY:
        case INS_UPDATE_BINARY:
        case INS_CREATE_FILE:
        case INS_PUT_DATA:
            return true;
        default:
            return false;
        }
    }

    private void assertSecureMessagingCounter() {
        if (smExpectedSSC == null || ssc == null) {
            return;
        }
        if (smExpectedSSC.length == 0 || ssc.length == 0) {
            return;
        }
        if (Util.arrayCompare(ssc, (short) 0, smExpectedSSC, (short) 0,
                (short) Math.min(ssc.length, smExpectedSSC.length)) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void updateSmExpectedCounter() {
        if (smExpectedSSC == null || ssc == null) {
            return;
        }
        short len = (short) Math.min(ssc.length, smExpectedSSC.length);
        Util.arrayCopyNonAtomic(ssc, (short) 0, smExpectedSSC, (short) 0, len);
    }

    private short getSmBufferOffset(short length) {
        if (hasMutuallyAuthenticated()) {
            return crypto.getApduBufferOffset(length);
        }
        if (hasPaceEstablished()) {
            return paceSecureMessaging.getApduBufferOffset(length);
        }
        return 0;
    }

    private SecureMessaging selectPaceSecureMessaging(String cipherAlgorithm) {
        if (cipherAlgorithm != null && cipherAlgorithm.startsWith("DESede")) {
            return paceSecureMessagingDes;
        }
        return paceSecureMessagingAes;
    }

    private void resetPaceSecureMessagingCounters(int blockSize) {
        if (paceSSC == null || paceSSC.length != blockSize) {
            paceSSC = new byte[blockSize];
        } else {
            Arrays.fill(paceSSC, (byte) 0);
        }
        if (paceExpectedSSC == null || paceExpectedSSC.length != blockSize) {
            paceExpectedSSC = new byte[blockSize];
        } else {
            Arrays.fill(paceExpectedSSC, (byte) 0);
        }
        paceContext.setPaceSendSequenceCounter(paceSSC);
    }

    private void assertPaceSecureMessagingCounter() {
        byte[] currentSSC = paceContext.getPaceSendSequenceCounter();
        if (currentSSC == null || paceExpectedSSC == null) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (Util.arrayCompare(currentSSC, (short) 0, paceExpectedSSC, (short) 0,
                (short) Math.min(currentSSC.length, paceExpectedSSC.length)) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void updatePaceExpectedCounter() {
        byte[] currentSSC = paceContext.getPaceSendSequenceCounter();
        if (currentSSC == null || paceExpectedSSC == null) {
            return;
        }
        short len = (short) Math.min(currentSSC.length, paceExpectedSSC.length);
        Util.arrayCopyNonAtomic(currentSSC, (short) 0, paceExpectedSSC, (short) 0, len);
    }

    private void resetSecureMessagingState() {
        updateSmExpectedCounter();
    }

    private short normalizeSmError(short reason) {
        return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    private short processPSO(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (!hasChipAuthenticated() || hasTerminalAuthenticated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (buffer[OFFSET_P1] != (byte) 0x00
                && buffer[OFFSET_P2] != P2_VERIFYCERT) {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        if (certificate.currentCertSubjectId[0] == 0) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        short lc = (short) (buffer[OFFSET_LC] & 0xFF);
        if (chainingOffset[0] > (short) (CHAINING_BUFFER_LENGTH - lc)) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        chainingOffset[0] = Util.arrayCopyNonAtomic(buffer, OFFSET_CDATA,
                chainingTmp, chainingOffset[0], lc);
        if (((byte) (buffer[OFFSET_CLA] & CHAIN_CLA) == CHAIN_CLA)) {
            return (short) 0;
        }
        short chainingTmpLength = chainingOffset[0];
        chainingOffset[0] = (short) 0;

        certificate.parseCertificate(chainingTmp, (short) 0, chainingTmpLength,
                false);
        if (!certificate.verify()) {
            ISOException.throwIt((short) 0x6300);
        }
        return (short) 0;
    }

    private short processMSE(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = (byte) (buffer[OFFSET_P1] & 0xff);
        byte p2 = (byte) (buffer[OFFSET_P2] & 0xff);
        short lc = (short) (buffer[OFFSET_LC] & 0xff);
        short buffer_p = OFFSET_CDATA;

        if (p1 == (byte) 0xC1 && p2 == (byte) 0xA4) {
            processPaceMSE(buffer, buffer_p, lc);
            return 0;
        }

        if (!hasEACKey() || !hasEACCertificate()) {
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        if ((!hasMutuallyAuthenticated() && !hasPaceEstablished()) || hasTerminalAuthenticated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (p1 == P1_SETFORCOMPUTATION && p2 == P2_AT) {
            processChipAuthenticationSetAt(buffer, buffer_p, lc);
            return 0;
        }
        if (p1 == P1_SETFORCOMPUTATION && p2 == P2_KAT) {

            short lastOffset = (short) (lc + OFFSET_CDATA);
            if (buffer_p > (short) (lastOffset - 2)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (buffer[buffer_p++] != (byte) 0x91) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short pubKeyLen = (short) (buffer[buffer_p++] & 0xFF);
            short pubKeyOffset = buffer_p;
            if (pubKeyOffset > (short) (lastOffset - pubKeyLen)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            buffer_p += pubKeyLen;
            short keyIdOffset = 0;
            short keyIdLength = 0;
            if (buffer_p != lastOffset) {
                if (buffer_p > (short) (lastOffset - 2)) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                if (buffer[buffer_p++] != (byte) 0x84) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                keyIdLength = (short) (buffer[buffer_p++] & 0xFF);
                keyIdOffset = buffer_p;
                if (keyIdOffset != (short) (lastOffset - keyIdLength)) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                // ignore the key id, we don't use it for now
            }
            if (!crypto.authenticateChip(buffer, pubKeyOffset, pubKeyLen)) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            volatileState[0] |= CHIP_AUTHENTICATED;
            if (hasPaceEstablished()) {
                applyChipAuthenticationSecureMessaging();
            }
            return 0;
        } else if (p1 == P1_SETFORVERIFICATION && (p2 == P2_DST || p2 == P2_AT)) {
            if (!hasChipAuthenticated() || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short lastOffset = (short) (lc + OFFSET_CDATA);
            if (buffer_p > (short) (lastOffset - 2)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (buffer[buffer_p++] != (byte) 0x83) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short subIdLen = (short) (buffer[buffer_p++] & 0xFF);
            if (buffer_p != (short) (lastOffset - subIdLen)) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            if (!certificate.selectSubjectId(buffer, buffer_p, subIdLen)) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
        } else {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        return 0;
    }

    private void processPaceMSE(byte[] buffer, short offset, short length) {
        short cursor = offset;
        short end = (short) (offset + length);
        String oid = null;
        byte keyReference = PaceSecrets.KEY_REF_MRZ;
        BigInteger keyId = null;

        while (cursor < end) {
            cursor = BERTLVScanner.readTag(buffer, cursor);
            short tag = BERTLVScanner.tag;
            cursor = BERTLVScanner.readLength(buffer, cursor);
            short valueOffset = cursor;
            short valueLength = BERTLVScanner.valueLength;
            if ((short) (cursor + valueLength) > end) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            switch (tag) {
            case (short) 0x80:
                byte[] oidBytes = new byte[valueLength];
                Util.arrayCopy(buffer, valueOffset, oidBytes, (short) 0, valueLength);
                oid = ASN1ObjectIdentifier.fromContents(oidBytes).getId();
                break;
            case (short) 0x83:
                keyReference = buffer[valueOffset];
                break;
            case (short) 0x84:
                keyId = new BigInteger(1, buffer, valueOffset, valueLength);
                break;
            case PACE_SECRET_ENTRY_TAG:
                if (valueLength < 2) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                paceSecrets.setSecret(buffer[valueOffset], buffer, (short) (valueOffset + 1), (short) (valueLength - 1));
                break;
            default:
                // ignore other tags for now
                break;
            }
            cursor = (short) (cursor + valueLength);
        }

        if (oid == null) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        PACEInfo paceInfo = selectPaceInfo(oid, keyId);
        if (paceInfo == null) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        paceContext.reset();
        volatileState[0] &= (byte) ~PACE_ESTABLISHED;
        paceContext.setProtocolOid(oid);
        paceContext.setKeyReference(keyReference);
        paceContext.setKeyId(keyId);
        paceContext.setParameterSpec(PACEInfo.toParameterSpec(paceInfo.getParameterId()));
        paceContext.setMappingType(PACEInfo.toMappingType(oid));
        paceContext.setAgreementAlgorithm(PACEInfo.toKeyAgreementAlgorithm(oid));
        paceContext.setCipherAlgorithm(PACEInfo.toCipherAlgorithm(oid));
        paceContext.setDigestAlgorithm(PACEInfo.toDigestAlgorithm(oid));
        paceContext.setKeyLength(PACEInfo.toKeyLength(oid));
        paceContext.setStep(PaceContext.Step.NONE);
        if (paceSSC != null) {
            Arrays.fill(paceSSC, (byte) 0);
        }
        if (paceExpectedSSC != null) {
            Arrays.fill(paceExpectedSSC, (byte) 0);
        }
        boolean mrzSeeded = paceDocumentNumber != null
                && paceDateOfBirth != null
                && paceDateOfExpiry != null;
        System.out.println("PACE MSE set OID=" + oid + " keyRef=" + keyReference
                + (mrzSeeded ? " [MRZ seeded]" : " [MRZ missing]"));
    }

    private void processChipAuthenticationSetAt(byte[] buffer, short offset, short length) {
        short cursor = offset;
        short end = (short) (offset + length);
        String oid = null;
        BigInteger keyId = null;

        while (cursor < end) {
            cursor = BERTLVScanner.readTag(buffer, cursor);
            short tag = BERTLVScanner.tag;
            cursor = BERTLVScanner.readLength(buffer, cursor);
            short valueOffset = cursor;
            short valueLength = BERTLVScanner.valueLength;
            if ((short) (cursor + valueLength) > end) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            switch (tag) {
            case (short) 0x80:
                byte[] oidBytes = new byte[valueLength];
                Util.arrayCopy(buffer, valueOffset, oidBytes, (short) 0, valueLength);
                oid = ASN1ObjectIdentifier.fromContents(oidBytes).getId();
                break;
            case (short) 0x83:
            case (short) 0x84:
                keyId = new BigInteger(1, buffer, valueOffset, valueLength);
                break;
            default:
                break;
            }
            cursor = (short) (cursor + valueLength);
        }

        if (oid == null) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        chipAuthProtocolOid = oid;
        chipAuthKeyId = keyId;

        String resolvedCipher;
        int resolvedKeyLength;
        try {
            resolvedCipher = ChipAuthenticationInfo.toCipherAlgorithm(oid);
            resolvedKeyLength = ChipAuthenticationInfo.toKeyLength(oid);
        } catch (NumberFormatException e) {
            ISOException.throwIt(SW_WRONG_DATA);
            return;
        }

        boolean paceActive = hasPaceEstablished();
        if (paceActive) {
            crypto.configureChipAuthentication(resolvedCipher, resolvedKeyLength);
        } else {
            if (resolvedCipher != null && resolvedCipher.startsWith("AES")) {
                System.out.println("CA MSE set AT requested AES but BAC session forces legacy DES secure messaging.");
            }
            crypto.configureChipAuthentication(null, 0);
        }

        chipAuthCipherAlgorithm = crypto.getChipAuthCipherAlgorithm();
        chipAuthKeyLength = crypto.getChipAuthKeyLength();

        System.out.println("CA MSE set AT oid=" + oid + " cipher=" + chipAuthCipherAlgorithm +
                " keyLength=" + chipAuthKeyLength + " paceActive=" + paceActive);
    }

    private void applyChipAuthenticationSecureMessaging() {
        if (!crypto.hasPendingSmKeys()) {
            return;
        }

        byte[] macKeyBytes = crypto.getPendingSmMacKey();
        byte[] encKeyBytes = crypto.getPendingSmEncKey();
        String cipherAlgorithm = crypto.getPendingSmCipherAlgorithm();
        int keyLengthBits = crypto.getPendingSmKeyLength();
        if (macKeyBytes == null || encKeyBytes == null || cipherAlgorithm == null) {
            crypto.clearPendingSmKeys();
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        SecretKey macKey = new SecretKeySpec(macKeyBytes, cipherAlgorithm);
        SecretKey encKey = new SecretKeySpec(encKeyBytes, cipherAlgorithm);
        SecureMessaging helper = selectPaceSecureMessaging(cipherAlgorithm);
        paceSecureMessaging = helper;
        paceSecureMessaging.setKeys(macKey, encKey);
        paceContext.setSessionMacKey(macKey);
        paceContext.setSessionEncKey(encKey);
        paceContext.setCipherAlgorithm(cipherAlgorithm);
        paceContext.setKeyLength(keyLengthBits);
        resetPaceSecureMessagingCounters(helper.getBlockSize());
        crypto.clearPendingSmKeys();
        System.out.println("Chip Authentication secure messaging upgraded to " + cipherAlgorithm);
    }

    private PACEInfo selectPaceInfo(String oid, BigInteger keyId) {
        PACEInfo[] infos = getPaceInfos();
        for (PACEInfo info : infos) {
            String infoOid = info.getObjectIdentifier();
            String infoAlias = info.getProtocolOIDString();
            if (oid.equals(infoOid) || (infoAlias != null && oid.equals(infoAlias))) {
                return info;
            }
        }
        return null;
    }

    private AccessKeySpec resolvePaceAccessKey(byte keyReference) {
        switch (keyReference) {
        case PaceSecrets.KEY_REF_MRZ:
            if (paceDocumentNumber == null || paceDateOfBirth == null || paceDateOfExpiry == null) {
                return null;
            }
            return new BACKey(paceDocumentNumber, paceDateOfBirth, paceDateOfExpiry);
        case PaceSecrets.KEY_REF_CAN:
            return buildPaceKeyFromSecret(keyReference, PACEKeySpec::createCANKey);
        case PaceSecrets.KEY_REF_PIN:
            return buildPaceKeyFromSecret(keyReference, PACEKeySpec::createPINKey);
        case PaceSecrets.KEY_REF_PUK:
            return buildPaceKeyFromSecret(keyReference, PACEKeySpec::createPUKKey);
        default:
            return null;
        }
    }

    private AccessKeySpec buildPaceKeyFromSecret(byte keyReference, Function<String, PACEKeySpec> factory) {
        byte[] secret = paceSecrets.getSecret(keyReference);
        if (secret == null || secret.length == 0) {
            return null;
        }
        String value = new String(secret, StandardCharsets.US_ASCII);
        return factory.apply(value);
    }

    private short readLength(byte[] buffer, short[] cursorRef) {
        short cursor = cursorRef[0];
        int first = buffer[cursor++] & 0xFF;
        int length;
        if ((first & 0x80) == 0) {
            length = first;
        } else {
            int count = first & 0x7F;
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (buffer[cursor++] & 0xFF);
            }
        }
        cursorRef[0] = cursor;
        return (short) length;
    }

    private short writeLength(byte[] buffer, short offset, short length) {
        if (length < 0x80) {
            buffer[offset++] = (byte) (length & 0xFF);
        } else {
            buffer[offset++] = (byte) 0x81;
            buffer[offset++] = (byte) (length & 0xFF);
        }
        return offset;
    }

    private String resolvePaceCipherTransformation(String cipherAlg) {
        if (cipherAlg != null && cipherAlg.startsWith("DESede")) {
            return "DESede/CBC/NoPadding";
        }
        return "AES/CBC/NoPadding";
    }

    private String inferMacAlgorithm(String cipherAlg) throws GeneralSecurityException {
        if (cipherAlg == null) {
            throw new GeneralSecurityException("Unknown cipher algorithm");
        }
        if (cipherAlg.startsWith("DESede")) {
            return "ISO9797ALG3WITHISO7816-4PADDING";
        } else if (cipherAlg.startsWith("AES")) {
            return "AESCMAC";
        }
        throw new GeneralSecurityException("Unsupported cipher algorithm: " + cipherAlg);
    }

    private short processGeneralAuthenticate(APDU apdu, boolean protectedApdu) {
        if (protectedApdu) {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }

        short lc = (short) (apdu.getBuffer()[OFFSET_LC] & 0xFF);
        short dataOffset = OFFSET_CDATA;
        System.out.println("PACE GA ins, p1=" + (apdu.getBuffer()[OFFSET_P1] & 0xFF) + " p2=" + (apdu.getBuffer()[OFFSET_P2] & 0xFF) + " lc=" + lc);
        if (lc > 0) {
            System.out.println("  GA data received (length=" + lc + " bytes)");
        }

        if (paceContext.getProtocolOid() == null) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        switch (paceContext.getStep()) {
        case NONE:
            return processPaceGeneralAuthenticateStep1(apdu, lc);
        case NONCE_SENT:
            return processPaceGeneralAuthenticateStep2(apdu, dataOffset, lc);
        case MAPPED:
            return processPaceGeneralAuthenticateStep3(apdu, dataOffset, lc);
        case KEY_AGREED:
            return processPaceGeneralAuthenticateStep4(apdu, dataOffset, lc);
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            return 0;
        }
    }

    private void processPutData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        short lc = (short) (buffer[OFFSET_LC] & 0xff);
        short p1 = (short) (buffer[OFFSET_P1] & 0xff);
        short p2 = (short) (buffer[OFFSET_P2] & 0xff);

        // sanity check
        if (buffer.length < (short) (buffer_p + lc)) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        if (p1 == 0xde) {
            handleLifecycleCommand(p2, lc, buffer, buffer_p);
            return;
        }

        if (p1 == 0 && p2 == CURRENT_DATE_TAG) {
            if (lc != (short) 6) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            certificate.setCurrentDate(buffer, buffer_p, lc);
            return;
        }

        assertPrePersonalized();

        if (p1 == 0 && p2 == PRIVMODULUS_TAG) {
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag ==
            // PRIVMODULUS_TAG
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p); // length ==
            // 00
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag == 04
            short modOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short modLength = BERTLVScanner.valueLength;

            if (buffer[modOffset] == 0) {
                modLength--;
                modOffset++;
            }

            keyStore.rsaPrivateKey.setModulus(buffer, modOffset, modLength);
            persistentState |= HAS_MODULUS;
        } else if (p1 == 0 && p2 == PRIVEXPONENT_TAG) {
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag ==
            // PRIVEXP_TAG
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p); // length ==
            // 00
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p); // tag == 04
            short expOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short expLength = BERTLVScanner.valueLength;

            // leading zero
            if (buffer[expOffset] == 0) {
                expLength--;
                expOffset++;
            }

            keyStore.rsaPrivateKey.setExponent(buffer, expOffset, expLength);
            persistentState |= HAS_EXPONENT;
        } else if (p1 == 0 && p2 == MRZ_TAG) {
            // data is BERTLV object with three objects; docNr, dataOfBirth,
            // dateOfExpiry
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short docNrOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short docNrLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short dobOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short dobLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();
            buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
            short doeOffset = BERTLVScanner.readLength(buffer, buffer_p);
            short doeLength = BERTLVScanner.valueLength;
            buffer_p = BERTLVScanner.skipValue();

            documentNumber = new byte[(short)(docNrLength+1)];
            Util.arrayCopyNonAtomic(buffer, docNrOffset, documentNumber,
                    (short) 0, docNrLength);
            documentNumber[docNrLength] = PassportInit.checkDigit(documentNumber,(short)0, docNrLength);

            paceDocumentNumber = toAsciiString(buffer, docNrOffset, docNrLength);
            paceDateOfBirth = toAsciiString(buffer, dobOffset, dobLength);
            paceDateOfExpiry = toAsciiString(buffer, doeOffset, doeLength);

            short keySeed_offset = init.computeKeySeed(buffer, docNrOffset,
                    docNrLength, dobOffset, dobLength, doeOffset, doeLength);

            short macKey_p = (short) (keySeed_offset + KEYMATERIAL_LENGTH);
            short encKey_p = (short) (keySeed_offset + KEYMATERIAL_LENGTH + KEY_LENGTH);
            crypto.deriveKey(buffer, keySeed_offset, KEYMATERIAL_LENGTH, PassportCrypto.MAC_MODE,
                    macKey_p);
            crypto.deriveKey(buffer, keySeed_offset, KEYMATERIAL_LENGTH, PassportCrypto.ENC_MODE,
                    encKey_p);
            keyStore.setMutualAuthenticationKeys(buffer, macKey_p, buffer,
                    encKey_p);
            persistentState |= HAS_MUTUALAUTHENTICATION_KEYS;
        } else if (p1 == 0 && p2 == PACE_SECRET_CONTAINER_TAG) {
            short start = buffer_p;
            short finish = (short) (buffer_p + lc);
            if (lc > 0) {
                short preview = BERTLVScanner.readTag(buffer, buffer_p);
                short tag = BERTLVScanner.tag;
                short valueOffset = BERTLVScanner.readLength(buffer, preview);
                short valueLength = BERTLVScanner.valueLength;
                if (tag == PACE_SECRET_CONTAINER_TAG) {
                    short nestedEnd = (short) (valueOffset + valueLength);
                    if (nestedEnd > finish) {
                        ISOException.throwIt(SW_WRONG_LENGTH);
                    }
                    buffer_p = valueOffset;
                    finish = nestedEnd;
                } else {
                    buffer_p = start;
                }
            }
            while (buffer_p < finish) {
                buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
                if (BERTLVScanner.tag != PACE_SECRET_ENTRY_TAG) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
                short entryOffset = BERTLVScanner.valueOffset;
                short entryLen = BERTLVScanner.valueLength;
                if (entryLen < 2) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                byte keyRef = buffer[entryOffset];
                paceSecrets.setSecret(keyRef, buffer, (short) (entryOffset + 1), (short) (entryLen - 1));
                buffer_p = (short) (entryOffset + entryLen);
            }
        } else if (p1 == 0 && p2 == ECPRIVATEKEY_TAG) {
            short finish = (short) (buffer_p + lc);
            while (buffer_p < finish) {
                buffer_p = BERTLVScanner.readTag(buffer, buffer_p);
                buffer_p = BERTLVScanner.readLength(buffer, buffer_p);
                short len = BERTLVScanner.valueLength;
                switch (BERTLVScanner.tag) {
                case (short) 0x81:
                    if (len == (short) 6) {
                        short e1 = Util.getShort(buffer, buffer_p);
                        short e2 = Util
                                .getShort(buffer, (short) (buffer_p + 2));
                        short e3 = Util
                                .getShort(buffer, (short) (buffer_p + 4));
                        keyStore.ecPrivateKey.setFieldF2M(e1, e2, e3);
                        keyStore.ecPublicKey.setFieldF2M(e1, e2, e3);
                    } else {
                        keyStore.ecPrivateKey.setFieldF2M(Util.getShort(buffer,
                                buffer_p));
                        keyStore.ecPublicKey.setFieldF2M(Util.getShort(buffer,
                                buffer_p));
                    }
                    break;
                case (short) 0x82:
                    keyStore.ecPrivateKey.setA(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setA(buffer, buffer_p, len);
                    break;
                case (short) 0x83:
                    keyStore.ecPrivateKey.setB(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setB(buffer, buffer_p, len);
                    break;
                case (short) 0x84:
                    keyStore.ecPrivateKey.setG(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setG(buffer, buffer_p, len);
                    break;
                case (short) 0x85:
                    keyStore.ecPrivateKey.setR(buffer, buffer_p, len);
                    keyStore.ecPublicKey.setR(buffer, buffer_p, len);
                    break;
                case (short) 0x86:
                    if (len == (short) 20) {
                        buffer_p--;
                        len++;
                        buffer[buffer_p] = 0x00;
                    }
                    keyStore.ecPrivateKey.setS(buffer, buffer_p, len);
                    break;
                case (short) 0x87:
                    // This is the k, ignore it
                    // short k = Util.getShort(buffer, buffer_p);
                    break;
                default:
                    ISOException.throwIt(SW_WRONG_DATA);
                break;
            }
            buffer_p = BERTLVScanner.skipValue();
        }
        if (keyStore.ecPrivateKey.isInitialized()) {
            persistentState |= HAS_EC_KEY;
        } else {
            ISOException.throwIt(SW_WRONG_DATA);
        }
    } else if (p2 == CVCERTIFICATE_TAG) {
        if ((byte) (persistentState & HAS_CVCERTIFICATE) == HAS_CVCERTIFICATE) {
            // We already have the certificate initialized
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        certificate.parseCertificate(buffer, buffer_p, lc, true);
        certificate.setRootCertificate(buffer, p1);
        persistentState |= HAS_CVCERTIFICATE;
    } else {
        ISOException.throwIt(SW_INCORRECT_P1P2);
    }
    }

    /**
     * Processes INTERNAL_AUTHENTICATE apdus, ie Active Authentication (AA). 
     * Receives a random and signs it.
     * 
     * @param apdu
     * @param protectedApdu true if Secure Messaging was used
     * @return
     */
    private short processInternalAuthenticate(APDU apdu, boolean protectedApdu) {
        if (!hasInternalAuthenticationKeys() || !hasSecureMessagingSession()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        short hdr_offset = protectedApdu ? getSmBufferOffset((short) 128) : 0;
        short hdr_len = 1;
        short m1_len = 106; // whatever
        short m1_offset = (short) (hdr_offset + hdr_len);
        short m2_len = 8;
        short m2_offset = (short) (m1_offset + m1_len);
        // we will write the hash over m2
        short m1m2hash_offset = (short) (m1_offset + m1_len);
        short m1m2hash_len = 20;
        short trailer_offset = (short) (m1m2hash_offset + m1m2hash_len);
        short trailer_len = 1;

        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[OFFSET_LC] & 0x00FF);
        if (bytesLeft != m2_len) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        // put m2 in place
        Util.arrayCopyNonAtomic(buffer, buffer_p, buffer, m2_offset, m2_len);

        // write some random data of m1_len
        // randomData.generateData(buffer, m1_offset, m1_length);
        for (short i = m1_offset; i < (short) (m1_offset + m1_len); i++) {
            buffer[i] = 0;
        }

        // calculate SHA1 hash over m1 and m2
        crypto.shaDigest.doFinal(buffer, m1_offset, (short) (m1_len + m2_len), buffer,
                m1m2hash_offset);
        crypto.shaDigest.reset();

        // write trailer
        buffer[trailer_offset] = (byte) 0xbc;

        // write header
        buffer[hdr_offset] = (byte) 0x6a;

        // encrypt the whole buffer with our AA private key
        short plaintext_len = (short) (hdr_len + m1_len + m1m2hash_len + trailer_len);
        // sanity check
        if (plaintext_len != 128) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }
        crypto.rsaCiph.init(keyStore.rsaPrivateKey, Cipher.MODE_ENCRYPT);
        short ciphertext_len = crypto.rsaCiph.doFinal(buffer, hdr_offset,
                plaintext_len, buffer, hdr_offset);
        // sanity check
        if (ciphertext_len != 128) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        return ciphertext_len;
    }

    /**
     * Processes incoming GET_CHALLENGE APDUs, as part of BAC or EAC.
     * 
     * Generates random 8 bytes, sends back result and stores result in rnd.
     * A GET_CHALLENGE APDU can be sent as part of BAC, or as part of
     * EAC (more specifically, Terminal Authentication (TA).
     * 
     * @param apdu
     *            is used for sending (8 bytes) only
     * @param protectedApdu true if Secure Messaging was used
     */
    private short processGetChallenge(APDU apdu, boolean protectedApdu, short le) {
        if (protectedApdu) {
            // we're doing TA
            if (!hasChipAuthenticated()
                    || certificate.cert1HolderReference[0] == (byte)0
                    || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            // we're doing BAC
            if (!hasMutualAuthenticationKeys() || hasSecureMessagingSession()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
        byte[] buffer = apdu.getBuffer();
        if (!protectedApdu) {
            le = apdu.setOutgoing();
        }
        // For the BAP challenge the length should be 8, for the EAP challenge
        // we guess other lenghts are fine too?
        if (le != 8) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        randomData.generateData(rnd, (short) 0, le);
        short bufferOffset = protectedApdu ? getSmBufferOffset(le)
                : (short) 0;
        Util.arrayCopyNonAtomic(rnd, (short) 0, buffer, bufferOffset, le);

        volatileState[0] |= CHALLENGED;

        return le;
    }

    /**
     * Processes incoming EXTERNAL_AUTHENTICATE APDUs, as part of BAC or EAC.
     *
     * An EXTERNAL_AUTHENTICATE can be the last step of BAC, or the last
     * step of Terminal Authentication (TA) when doing EAC.
     * 
     * @param apdu
     *            the APDU
     * @param protectedApdu true if Secure Messaging was used
     * @return length of response APDU
     */
    private short processMutualAuthenticate(APDU apdu, boolean protectedApdu) {
        if (protectedApdu) {
            // we're doing EAC
            if (!hasChipAuthenticated() || !isChallenged()
                    || certificate.currentCertSubjectId[0] == (byte)0
                    || hasTerminalAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            byte[] buffer = apdu.getBuffer();
            short buffer_p = OFFSET_CDATA;
            short lc = (short) (buffer[OFFSET_LC] & 0xFF);
            setNoChallenged();
            if (!crypto.eacVerifySignature(certificate.currentCertPublicKey, rnd,
                    documentNumber, buffer, buffer_p, lc)) {
                certificate.clear();
                ISOException.throwIt((short) 0x6300);
            }
            certificate.clear();
            volatileState[0] |= TERMINAL_AUTHENTICATED;
            return 0;
        } else {
        // we're doing BAC
        if (!isChallenged() || hasMutuallyAuthenticated()) {
               ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
           }

        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[OFFSET_LC] & 0x00FF);
        short e_ifd_length = RND_LENGTH + RND_LENGTH + KEYMATERIAL_LENGTH;

        // incoming message is e_ifd || m_ifd
        // where e_ifd == E_KENC(rnd_ifd || rnd_icc || k_ifd)
        if (bytesLeft != (short) (e_ifd_length + MAC_LENGTH))
            ISOException.throwIt(SW_WRONG_LENGTH);

        short e_ifd_p = OFFSET_CDATA;
        short m_ifd_p = (short) (e_ifd_p + e_ifd_length);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        // buffer[OFFSET_CDATA ... +40] consists of e_ifd || m_ifd
        // verify checksum m_ifd of cryptogram e_ifd
        crypto.initMac(Signature.MODE_VERIFY);
        if (!crypto.verifyMacFinal(buffer, e_ifd_p, e_ifd_length, buffer,
                m_ifd_p))
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        // decrypt e_ifd into buffer[0] where buffer = rnd.ifd || rnd.icc ||
        // k.ifd
        crypto.decryptInit();
        short plaintext_len = crypto.decryptFinal(buffer, e_ifd_p,
                e_ifd_length, buffer, (short) 0);
        if (plaintext_len != e_ifd_length) // sanity check
            ISOException.throwIt(SW_INTERNAL_ERROR);

        short rnd_ifd_p = 0;
        short rnd_icc_p = RND_LENGTH;
        short k_ifd_p = (short) (rnd_icc_p + RND_LENGTH);

        /*
         * we use apdu buffer for writing intermediate data in buffer with
         * following pointers
         */
        short k_icc_p = (short) (k_ifd_p + KEYMATERIAL_LENGTH);
        short keySeed_p = (short) (k_icc_p + KEYMATERIAL_LENGTH);
        short keys_p = (short) (keySeed_p + KEYMATERIAL_LENGTH);

        // verify that rnd.icc equals value generated in getChallenge
        if (Util.arrayCompare(buffer, rnd_icc_p, rnd, (short) 0, RND_LENGTH) != 0)
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        // generate keying material k.icc
        randomData.generateData(buffer, k_icc_p, KEYMATERIAL_LENGTH);

        // calculate keySeed for session keys by xorring k_ifd and k_icc
        PassportUtil.xor(buffer, k_ifd_p, buffer, k_icc_p, buffer, keySeed_p,
                KEYMATERIAL_LENGTH);

        // calculate session keys
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.MAC_MODE, keys_p);
        short macKey_p = keys_p;
        keys_p += KEY_LENGTH;
        crypto.deriveKey(buffer, keySeed_p, KEYMATERIAL_LENGTH, PassportCrypto.ENC_MODE, keys_p);
        short encKey_p = keys_p;
        keys_p += KEY_LENGTH;
        keyStore.setSecureMessagingKeys(buffer, macKey_p, buffer, encKey_p);

        // compute ssc
        PassportCrypto.computeSSC(buffer, rnd_icc_p, buffer, rnd_ifd_p, ssc);

        // create response in buffer where response = rnd.icc || rnd.ifd ||
        // k.icc
        PassportUtil.swap(buffer, rnd_icc_p, rnd_ifd_p, RND_LENGTH);
        Util.arrayCopyNonAtomic(buffer, k_icc_p, buffer, (short) (2 * RND_LENGTH),
                KEYMATERIAL_LENGTH);

        // make buffer encrypted using k_enc
        crypto.encryptInit();
        short ciphertext_len = crypto.encryptFinal(buffer, (short) 0,
                (short) (2 * RND_LENGTH + KEYMATERIAL_LENGTH), buffer,
                (short) 0);

        // create m_icc which is a checksum of response
        crypto.initMac(Signature.MODE_SIGN);
        crypto.createMacFinal(buffer, (short) 0, ciphertext_len, buffer,
                ciphertext_len);

        setNoChallenged();
        volatileState[0] |= MUTUAL_AUTHENTICATED;
        resetSecureMessagingState();

        return (short) (ciphertext_len + MAC_LENGTH);
        
        }
    }

    /**
     * Processes incoming SELECT_FILE APDUs.
     * 
     * @param apdu
     *            where the first 2 data bytes encode the file to select.
     */
    private void processSelectFile(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[OFFSET_LC] & 0x00FF);

        if (lc != 2)
            ISOException.throwIt(SW_WRONG_LENGTH);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        short fid = Util.getShort(buffer, OFFSET_CDATA);

        boolean openReadFile = isOpenReadFile(fid);
        boolean openlySelectable = (fid == FileSystem.EF_COM_FID || fid == FileSystem.EF_SOD_FID);
        if (isLocked() && !hasSecureMessagingSession() && fid != FileSystem.EF_CVCA_FID && !openReadFile && !openlySelectable) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (fileSystem.exists(fid)) {
            selectedFile = fid;
            volatileState[0] |= FILE_SELECTED;
            return;
        }
        setNoFileSelected();
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    /**
     * Processes incoming READ_BINARY APDUs. Returns data of the currently
     * selected file.
     * 
     * @param apdu
     *            where the offset is carried in header bytes p1 and p2.
     * @param le
     *            expected length by terminal
     * @return length of the response APDU
     */
    private short processReadBinary(APDU apdu, short le, boolean protectedApdu) {
        boolean cardAccessRead = (selectedFile == FileSystem.EF_CVCA_FID);
        boolean openReadAllowed = isOpenReadFile(selectedFile);
        if (!hasSecureMessagingSession() && !cardAccessRead && !openReadAllowed) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!hasFileSelected()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];

        short offset = Util.makeShort(p1, p2);

        short effectiveLe = le;
        if (!protectedApdu) {
            effectiveLe = apdu.setOutgoing();
        }

        byte[] file = fileSystem.getFile(selectedFile);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        short len;
        short fileSize = fileSystem.getFileSize(selectedFile);

        len = PassportUtil.min((short) (buffer.length - 37),
                (short) (fileSize - offset));
        // FIXME: 37 magic
        len = PassportUtil.min(len, (short) buffer.length);
        len = PassportUtil.min(effectiveLe, len);
        short bufferOffset = protectedApdu ? getSmBufferOffset(len) : 0;
        Util.arrayCopyNonAtomic(file, offset, buffer, bufferOffset, len);

        return len;
    }

    private short processPaceGeneralAuthenticateStep1(APDU apdu, short lc) {
        System.out.println("PACE step1");
        if (lc != 0) {
            // Expecting empty command data for step 1
        }
        AccessKeySpec accessKeySpec = resolvePaceAccessKey(paceContext.getKeyReference());
        if (accessKeySpec == null) {
            System.out.println("PACE Step1 missing access key for ref=" + paceContext.getKeyReference());
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        SecretKey staticKey;
        try {
            staticKey = PACEProtocol.deriveStaticPACEKey(accessKeySpec, paceContext.getProtocolOid());
        } catch (GeneralSecurityException e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
            return 0;
        }

        byte[] encryptedNonce;
        try {
            String cipherAlgorithm = paceContext.getCipherAlgorithm();
            String transformation = resolvePaceCipherTransformation(cipherAlgorithm);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            int blockSize = cipher.getBlockSize();
            byte[] nonce = new byte[blockSize];
            randomData.generateData(nonce, (short) 0, (short) nonce.length);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, staticKey, new IvParameterSpec(new byte[blockSize]));
            encryptedNonce = cipher.doFinal(nonce);
            paceContext.setNonceS(nonce);
        } catch (GeneralSecurityException e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
            return 0;
        }

        paceContext.setStaticKey(staticKey);
        paceContext.setStep(PaceContext.Step.NONCE_SENT);

        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        buffer[offset++] = (byte) 0x7C;
        buffer[offset++] = (byte) (encryptedNonce.length + 2);
        buffer[offset++] = (byte) 0x80;
        buffer[offset++] = (byte) encryptedNonce.length;
        Util.arrayCopy(encryptedNonce, (short) 0, buffer, offset, (short) encryptedNonce.length);
        offset += encryptedNonce.length;

        return offset;
    }

    private short processPaceGeneralAuthenticateStep2(APDU apdu, short dataOffset, short lc) {
        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        MappingType mappingType = paceContext.getMappingType();
        AlgorithmParameterSpec staticParams = paceContext.getParameterSpec();
        if (mappingType == null || staticParams == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short cursor = dataOffset;
        if (buffer[cursor++] != (byte) 0x7C) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short[] cursorHolder = new short[] { cursor };
        short containerLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        short containerEnd = (short) (cursor + containerLength);
        if (cursor >= containerEnd || buffer[cursor++] != (byte) 0x81) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        cursorHolder[0] = cursor;
        short valueLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        if ((short) (cursor + valueLength) > containerEnd) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        switch (mappingType) {
        case GM: {
            if (!(staticParams instanceof java.security.spec.ECParameterSpec)) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            byte[] mappingData = new byte[valueLength];
            Util.arrayCopy(buffer, cursor, mappingData, (short) 0, valueLength);
            cursor += valueLength;
            if (cursor != containerEnd) {
                ISOException.throwIt(SW_WRONG_DATA);
            }

            try {
                PublicKey mappingTerminalPublicKey = PACEProtocol.decodePublicKeyFromSmartCard(mappingData, staticParams);
                String agreementAlg = paceContext.getAgreementAlgorithm();
                if (!"ECDH".equalsIgnoreCase(agreementAlg)) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                keyPairGenerator.initialize(staticParams);
                KeyPair mappingKeyPair = keyPairGenerator.generateKeyPair();

                ECPublicKey terminalPublic = (ECPublicKey) mappingTerminalPublicKey;
                ECPrivateKey chipPrivate = (ECPrivateKey) mappingKeyPair.getPrivate();
                java.security.spec.ECParameterSpec ecSpec = terminalPublic.getParams();
                java.security.spec.ECPoint sharedPoint = org.jmrtd.Util.multiply(chipPrivate.getS(), terminalPublic.getW(), ecSpec);

                AlgorithmParameterSpec ephemeralParams = PACEProtocol.mapNonceGMWithECDH(paceContext.getNonceS(), sharedPoint,
                        ecSpec);

                paceContext.setMappingKeyPair(mappingKeyPair);
                paceContext.setEphemeralParameterSpec(ephemeralParams);
                paceContext.setStep(PaceContext.Step.MAPPED);

                ECPublicKey chipPublic = (ECPublicKey) mappingKeyPair.getPublic();
                byte[] encodedPoint = org.jmrtd.Util.ecPoint2OS(chipPublic.getW(), ecSpec.getCurve().getField().getFieldSize());

                short offset = 0;
                buffer[offset++] = (byte) 0x7C;
                offset = writeLength(buffer, offset, (short) (2 + encodedPoint.length));
                buffer[offset++] = (byte) 0x82;
                offset = writeLength(buffer, offset, (short) encodedPoint.length);
                Util.arrayCopyNonAtomic(encodedPoint, (short) 0, buffer, offset, (short) encodedPoint.length);
                offset += encodedPoint.length;

                return offset;
            } catch (GeneralSecurityException e) {
                ISOException.throwIt(SW_INTERNAL_ERROR);
                return 0;
            }
        }
        case IM: {
            if (!(staticParams instanceof java.security.spec.ECParameterSpec)) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            byte[] pcdNonce = new byte[valueLength];
            Util.arrayCopy(buffer, cursor, pcdNonce, (short) 0, valueLength);
            cursor += valueLength;
            if (cursor < containerEnd) {
                if (buffer[cursor++] != (byte) 0x82) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
                cursorHolder[0] = cursor;
                short paddingLength = readLength(buffer, cursorHolder);
                cursor = cursorHolder[0];
                if (paddingLength != 0 || cursor != containerEnd) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
            } else if (cursor != containerEnd) {
                ISOException.throwIt(SW_WRONG_DATA);
            }

            try {
                AlgorithmParameterSpec ephemeralParams = PACEProtocol.mapNonceIMWithECDH(paceContext.getNonceS(), pcdNonce,
                        paceContext.getCipherAlgorithm(), (java.security.spec.ECParameterSpec) staticParams);
                paceContext.setEphemeralParameterSpec(ephemeralParams);
                paceContext.setStep(PaceContext.Step.MAPPED);

                short offset = 0;
                buffer[offset++] = (byte) 0x7C;
                offset = writeLength(buffer, offset, (short) 2);
                buffer[offset++] = (byte) 0x82;
                buffer[offset++] = 0x00;
                return offset;
            } catch (GeneralSecurityException e) {
                ISOException.throwIt(SW_INTERNAL_ERROR);
                return 0;
            }
        }
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            return 0;
        }
    }

    private short processPaceGeneralAuthenticateStep3(APDU apdu, short dataOffset, short lc) {
        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        AlgorithmParameterSpec ephemeralParams = paceContext.getEphemeralParameterSpec();
        if (ephemeralParams == null || !(ephemeralParams instanceof java.security.spec.ECParameterSpec)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        short cursor = dataOffset;
        if (buffer[cursor++] != (byte) 0x7C) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short[] cursorHolder = new short[] { cursor };
        short containerLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        short containerEnd = (short) (cursor + containerLength);
        if (cursor >= containerEnd || buffer[cursor++] != (byte) 0x83) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        cursorHolder[0] = cursor;
        short terminalPublicLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        if ((short) (cursor + terminalPublicLength) > containerEnd) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        byte[] terminalPublicBytes = new byte[terminalPublicLength];
        Util.arrayCopy(buffer, cursor, terminalPublicBytes, (short) 0, terminalPublicLength);
        cursor += terminalPublicLength;
        if (cursor != containerEnd) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        try {
            PublicKey terminalEphemeralKey = PACEProtocol.decodePublicKeyFromSmartCard(terminalPublicBytes, ephemeralParams);
            String agreementAlg = paceContext.getAgreementAlgorithm();
            if (!"ECDH".equalsIgnoreCase(agreementAlg)) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(ephemeralParams);
            KeyPair chipEphemeralKeyPair = keyPairGenerator.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance(agreementAlg, BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey chipPrivate = chipEphemeralKeyPair.getPrivate();
            keyAgreement.init(chipPrivate);
            PublicKey adjustedTerminalKey = PACEProtocol.updateParameterSpec(terminalEphemeralKey, chipPrivate);
            keyAgreement.doPhase(adjustedTerminalKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            paceContext.setChipEphemeralKeyPair(chipEphemeralKeyPair);
            paceContext.setTerminalPublicKey(terminalEphemeralKey);
            paceContext.setSharedSecret(Arrays.copyOf(sharedSecret, sharedSecret.length));
            paceContext.setStep(PaceContext.Step.KEY_AGREED);

            ECPublicKey chipPublic = (ECPublicKey) chipEphemeralKeyPair.getPublic();
            java.security.spec.ECParameterSpec ecSpec = (java.security.spec.ECParameterSpec) ephemeralParams;
            byte[] encodedPoint = org.jmrtd.Util.ecPoint2OS(chipPublic.getW(), ecSpec.getCurve().getField().getFieldSize());

            short offset = 0;
            buffer[offset++] = (byte) 0x7C;
            offset = writeLength(buffer, offset, (short) (2 + encodedPoint.length));
            buffer[offset++] = (byte) 0x84;
            offset = writeLength(buffer, offset, (short) encodedPoint.length);
            Util.arrayCopyNonAtomic(encodedPoint, (short) 0, buffer, offset, (short) encodedPoint.length);
            offset += encodedPoint.length;

            return offset;
        } catch (GeneralSecurityException e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
            return 0;
        }
    }

    private short processPaceGeneralAuthenticateStep4(APDU apdu, short dataOffset, short lc) {
        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        if (paceContext.getSharedSecret() == null || paceContext.getChipEphemeralKeyPair() == null
                || paceContext.getTerminalPublicKey() == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short cursor = dataOffset;
        if (buffer[cursor++] != (byte) 0x7C) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short[] cursorHolder = new short[] { cursor };
        short containerLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        short containerEnd = (short) (cursor + containerLength);
        if (cursor >= containerEnd || buffer[cursor++] != (byte) 0x85) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        cursorHolder[0] = cursor;
        short tokenLength = readLength(buffer, cursorHolder);
        cursor = cursorHolder[0];
        if (tokenLength != 8 || (short) (cursor + tokenLength) > containerEnd) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        byte[] terminalToken = new byte[tokenLength];
        Util.arrayCopy(buffer, cursor, terminalToken, (short) 0, tokenLength);
        cursor += tokenLength;
        if (cursor != containerEnd) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        try {
            byte[] sharedSecret = paceContext.getSharedSecret();
            String cipherAlg = paceContext.getCipherAlgorithm();
            int keyLength = paceContext.getKeyLength();
            SecretKey encKey = org.jmrtd.Util.deriveKey(sharedSecret, cipherAlg, keyLength, org.jmrtd.Util.ENC_MODE);
            SecretKey macKey = org.jmrtd.Util.deriveKey(sharedSecret, cipherAlg, keyLength, org.jmrtd.Util.MAC_MODE);

            String macAlgorithm = inferMacAlgorithm(cipherAlg);
            Mac mac = Mac.getInstance(macAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            mac.init(macKey);
            byte[] chipPublicDataForTerminalToken = PACEProtocol.encodePublicKeyDataObject(paceContext.getProtocolOid(), paceContext.getChipEphemeralKeyPair().getPublic());
            byte[] expectedTerminalTokenFull = mac.doFinal(chipPublicDataForTerminalToken);
            byte[] expectedTerminalToken = new byte[8];
            Util.arrayCopyNonAtomic(expectedTerminalTokenFull, (short) 0, expectedTerminalToken, (short) 0, (short) expectedTerminalToken.length);
            if (Util.arrayCompare(expectedTerminalToken, (short) 0, terminalToken, (short) 0, (short) terminalToken.length) != 0) {
                System.out.println("PACE Step4 terminal token mismatch detected.");
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            mac.init(macKey);
            byte[] terminalPublicDataForChipToken = PACEProtocol.encodePublicKeyDataObject(paceContext.getProtocolOid(), paceContext.getTerminalPublicKey());
            byte[] chipTokenFull = mac.doFinal(terminalPublicDataForChipToken);
            byte[] chipToken = new byte[8];
            Util.arrayCopyNonAtomic(chipTokenFull, (short) 0, chipToken, (short) 0, (short) chipToken.length);
            System.out.println("PACE Step4 chip token generated.");

            SecureMessaging helper = selectPaceSecureMessaging(cipherAlg);
            paceSecureMessaging = helper;
            paceSecureMessaging.setKeys(macKey, encKey);
            paceContext.setSessionEncKey(encKey);
            paceContext.setSessionMacKey(macKey);
            paceContext.setCipherAlgorithm(cipherAlg);
            paceContext.setKeyLength(keyLength);
            resetPaceSecureMessagingCounters(helper.getBlockSize());
            paceContext.setSharedSecret(Arrays.copyOf(sharedSecret, sharedSecret.length));
            paceContext.setStep(PaceContext.Step.TOKENS_VERIFIED);
            volatileState[0] |= PACE_ESTABLISHED;

            short offset = 0;
            buffer[offset++] = (byte) 0x7C;
            offset = writeLength(buffer, offset, (short) (2 + chipToken.length));
            buffer[offset++] = (byte) 0x86;
            offset = writeLength(buffer, offset, (short) chipToken.length);
            Util.arrayCopyNonAtomic(chipToken, (short) 0, buffer, offset, (short) chipToken.length);
            offset += chipToken.length;

            return offset;
        } catch (GeneralSecurityException e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
            return 0;
        }
    }

    /**
     * Processes and UPDATE_BINARY apdu. Writes data in the currently selected
     * file.
     * 
     * @param apdu
     *            carries the offset where to write date in header bytes p1 and
     *            p2.
     */
    private void processUpdateBinary(APDU apdu) {
        if (!hasFileSelected()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        assertPrePersonalized();

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];
        short offset = Util.makeShort(p1, p2);

        short readCount = (short) (buffer[ISO7816.OFFSET_LC] & 0xff);
        readCount = apdu.setIncomingAndReceive();

        while (readCount > 0) {
            fileSystem.writeData(selectedFile, offset, buffer, OFFSET_CDATA,
                    readCount);
            offset += readCount;
            readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
    }

    /**
     * Processes and CREATE_FILE apdu.
     * 
     * This functionality is only partly implemented. Only non-directories
     * (files) can be created, all options for CREATE_FILE are ignored.
     * 
     * @param apdu
     *            containing 6 bytes: 0x64 || (1 byte) || size (2) || fid (2)
     */
    private void processCreateFile(APDU apdu) {
        assertPrePersonalized();

        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[OFFSET_LC] & 0xff);

        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }
        if (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
            // need all data in one APDU.
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }

        if (lc < (short) 6 || (buffer[OFFSET_CDATA + 1] & 0xff) < 4)
            ISOException.throwIt(SW_WRONG_LENGTH);

        if (buffer[OFFSET_CDATA] != 0x63)
            ISOException.throwIt(SW_DATA_INVALID);

        short size = Util.makeShort(buffer[(short) (OFFSET_CDATA + 2)],
                buffer[(short) (OFFSET_CDATA + 3)]);

        short fid = Util.makeShort(buffer[(short) (OFFSET_CDATA + 4)],
                buffer[(short) (OFFSET_CDATA + 5)]);

        if(fid == FileSystem.EF_CVCA_FID) {
           fileSystem.createFile(fid, size, certificate);
        }else{
           fileSystem.createFile(fid, size);
        }
    }

    public static boolean hasInternalAuthenticationKeys() {
        return (persistentState & (HAS_EXPONENT | HAS_MODULUS)) == (HAS_EXPONENT | HAS_MODULUS);
    }

    public static boolean hasMutualAuthenticationKeys() {
        return (persistentState & HAS_MUTUALAUTHENTICATION_KEYS) == HAS_MUTUALAUTHENTICATION_KEYS;
    }

    public static boolean hasEACKey() {
        return (persistentState & HAS_EC_KEY) == HAS_EC_KEY;
    }

    public static boolean hasEACCertificate() {
        return (persistentState & HAS_CVCERTIFICATE) == HAS_CVCERTIFICATE;
    }

    public static void setNoFileSelected() {
        if (hasFileSelected()) {
            volatileState[0] ^= FILE_SELECTED;
        }
    }

    public static void setNoChallenged() {
        if ((volatileState[0] & CHALLENGED) == CHALLENGED) {
            volatileState[0] ^= CHALLENGED;
        }
    }

    public static boolean hasFileSelected() {
        return (volatileState[0] & FILE_SELECTED) == FILE_SELECTED;
    }

    public static boolean isChallenged() {
        return (volatileState[0] & CHALLENGED) == CHALLENGED;
    }

	/** Has BAC been completed? */
    public static boolean hasMutuallyAuthenticated() {
        return (volatileState[0] & MUTUAL_AUTHENTICATED) == MUTUAL_AUTHENTICATED;
    }
    
    public static boolean hasChipAuthenticated() {
        return (volatileState[0] & CHIP_AUTHENTICATED) == CHIP_AUTHENTICATED;
    }

    public static boolean hasTerminalAuthenticated() {
        return (volatileState[0] & TERMINAL_AUTHENTICATED) == TERMINAL_AUTHENTICATED;
    }

    public static boolean hasPaceEstablished() {
        return (volatileState[0] & PACE_ESTABLISHED) == PACE_ESTABLISHED;
    }

    private boolean hasSecureMessagingSession() {
        return hasMutuallyAuthenticated() || hasPaceEstablished();
    }

    private static byte getLifecycleState() {
        return (byte) (persistentState & LIFECYCLE_STATE_MASK);
    }

    private static void setLifecycleState(byte newState) {
        persistentState = (byte) ((persistentState & ~LIFECYCLE_STATE_MASK) | newState);
    }

    private static void transitionLifecycle(byte targetState) {
        byte current = getLifecycleState();
        if (current == targetState) {
            System.out.println("Lifecycle already in state " + describeLifecycleState(targetState));
            return;
        }
        switch (targetState) {
        case LIFECYCLE_PERSONALIZED:
            if (current != LIFECYCLE_PREPERSONALIZED) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            setLifecycleState(targetState);
            System.out.println("Lifecycle transitioned to PERSONALIZED state.");
            break;
        case LIFECYCLE_LOCKED:
            if (current != LIFECYCLE_PERSONALIZED) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            setLifecycleState(targetState);
            System.out.println("Lifecycle transitioned to LOCKED state.");
            break;
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    private static String describeLifecycleState(byte state) {
        switch (state) {
        case LIFECYCLE_PREPERSONALIZED:
            return "PRE-PERSONALIZED";
        case LIFECYCLE_PERSONALIZED:
            return "PERSONALIZED";
        case LIFECYCLE_LOCKED:
            return "LOCKED";
        default:
            return "UNKNOWN";
        }
    }

    private static boolean isPrePersonalized() {
        return getLifecycleState() == LIFECYCLE_PREPERSONALIZED;
    }

    public static boolean isLocked() {
        return getLifecycleState() == LIFECYCLE_LOCKED;
    }

    private boolean allowOpenComSodReads() {
        return (persistentState & ALLOW_OPEN_COM_SOD_READS) != 0;
    }

    private boolean isOpenReadFile(short fid) {
        if (!isLocked()) {
            return false;
        }
        if (!allowOpenComSodReads()) {
            return false;
        }
        return fid == FileSystem.EF_SOD_FID || fid == FileSystem.EF_COM_FID;
    }

    private void setOpenComSodReads(boolean allow) {
        if (allow) {
            persistentState = (byte) (persistentState | ALLOW_OPEN_COM_SOD_READS);
        } else {
            persistentState = (byte) (persistentState & ~ALLOW_OPEN_COM_SOD_READS);
        }
    }

    private void assertPrePersonalized() {
        if (isPrePersonalized()) {
            return;
        }
        if (isLocked()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    private void handleLifecycleCommand(short p2, short lc, byte[] buffer, short dataOffset) {
        switch (p2) {
        case (short) 0xAF:
            if (lc != 0) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            transitionLifecycle(LIFECYCLE_PERSONALIZED);
            break;
        case (short) 0xAD:
            if (lc != 0) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            transitionLifecycle(LIFECYCLE_LOCKED);
            break;
        case (short) 0xFE:
            if (lc != 1) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            byte mode = buffer[dataOffset];
            if (mode == 0x00) {
                setOpenComSodReads(false);
                System.out.println("Open COM/SOD reads disabled.");
            } else if (mode == 0x01) {
                setOpenComSodReads(true);
                System.out.println("Open COM/SOD reads enabled.");
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        default:
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
    }

    private static String toAsciiString(byte[] data, short offset, short length) {
        if (data == null || length == 0) {
            return null;
        }
        char[] chars = new char[length];
        for (short i = 0; i < length; i++) {
            chars[i] = (char) (data[(short) (offset + i)] & 0xFF);
        }
        return new String(chars);
    }

    private static String toHex(byte[] data, short offset, short length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (short i = 0; i < length; i++) {
            int value = data[(short) (offset + i)] & 0xFF;
            if (value < 0x10) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(value).toUpperCase());
        }
        return sb.toString();
    }

    private PACEInfo[] getPaceInfos() {
        if (cachedPaceInfos != null) {
            return cachedPaceInfos;
        }
        byte[] file = fileSystem.getFile(FileSystem.EF_CVCA_FID);
        short fileSize = fileSystem.getFileSize(FileSystem.EF_CVCA_FID);
        if (file == null || fileSize <= 0) {
            return new PACEInfo[0];
        }
        try (ByteArrayInputStream in = new ByteArrayInputStream(file, 0, fileSize)) {
            CardAccessFile cardAccessFile = new CardAccessFile(in);
            java.util.List<PACEInfo> infos = new java.util.ArrayList<>();
            java.util.Collection<SecurityInfo> securityInfos = cardAccessFile.getSecurityInfos();
            if (securityInfos != null) {
                for (SecurityInfo info : securityInfos) {
                    if (info instanceof PACEInfo) {
                        infos.add((PACEInfo) info);
                    }
                }
            }
            cachedPaceInfos = infos.toArray(new PACEInfo[0]);
        } catch (IOException e) {
            cachedPaceInfos = new PACEInfo[0];
        }
        return cachedPaceInfos;
    }

}
