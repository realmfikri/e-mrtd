package cardapplet;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Educational eMRTD-like Java Card applet.
 *
 * <p>Non-production demo code: this implementation intentionally keeps data and policy handling
 * simple to focus on command flow and status-word behavior.</p>
 */
public final class EducationalEmrtdApplet extends Applet {

    private static final byte INS_SELECT = (byte) 0xA4;
    private static final byte INS_READ_BINARY = (byte) 0xB0;

    private static final short SW_FILE_NOT_FOUND = (short) 0x6A82;
    private static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;
    private static final short SW_WRONG_LENGTH = (short) 0x6700;
    private static final short SW_WRONG_P1P2 = (short) 0x6A86;
    private static final short SW_OFFSET_INVALID = (short) 0x6B00;

    private static final short EF_COM_FID = (short) 0x011E;
    private static final short EF_DG1_FID = (short) 0x0101;

    // Demo-only short file identifiers for READ BINARY SFI mode.
    private static final byte SFI_COM = (byte) 0x1E;
    private static final byte SFI_DG1 = (byte) 0x01;

    // Flip to true to demonstrate 6982 on DG1 reads when access control is not implemented.
    private static final boolean ENFORCE_DG1_READ_POLICY = false;

    // Persistent demo data.
    private final byte[] efCom = {
        0x60, 0x16, 0x5F, 0x01, 0x04, 0x30, 0x31, 0x30, 0x37,
        0x5F, 0x36, 0x06, 0x30, 0x34, 0x30, 0x30, 0x30, 0x31,
        0x5C, 0x06, 0x61, 0x75, 0x63, 0x6E, 0x7F, 0x61
    };

    private final byte[] efDg1 = {
        0x61, 0x1F, 0x5F, 0x1F, 0x1C,
        0x50, 0x3C, 0x55, 0x54, 0x4F, 0x45, 0x52, 0x49, 0x4B, 0x53,
        0x53, 0x4F, 0x4E, 0x3C, 0x3C, 0x41, 0x4E, 0x4E, 0x41, 0x3C,
        0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C
    };

    private short selectedEfFid;

    private EducationalEmrtdApplet() {
        selectedEfFid = (short) 0x0000;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EducationalEmrtdApplet();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SELECT:
                processSelect(apdu, buffer);
                return;
            case INS_READ_BINARY:
                processReadBinary(apdu, buffer);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processSelect(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        byte p1 = buffer[ISO7816.OFFSET_P1];

        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        if (p1 == (byte) 0x04) {
            selectByAid(buffer, lc);
            return;
        }

        if (p1 == (byte) 0x00 || p1 == (byte) 0x02) {
            if (lc != (short) 2) {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            short fid = Util.makeShort(buffer[ISO7816.OFFSET_CDATA], buffer[(short) (ISO7816.OFFSET_CDATA + 1)]);
            selectByFid(fid);
            return;
        }

        ISOException.throwIt(SW_WRONG_P1P2);
    }

    private void selectByAid(byte[] buffer, short lc) {
        AID thisAid = getAID();
        if (!thisAid.partialEquals(buffer, ISO7816.OFFSET_CDATA, (byte) lc)) {
            ISOException.throwIt(SW_FILE_NOT_FOUND);
        }

        // Keep EF selection unchanged on DF select.
    }

    private void selectByFid(short fid) {
        if (fid != EF_COM_FID && fid != EF_DG1_FID) {
            ISOException.throwIt(SW_FILE_NOT_FOUND);
        }
        selectedEfFid = fid;
    }

    private void processReadBinary(APDU apdu, byte[] buffer) {
        short offset;
        short targetEf = selectedEfFid;

        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if ((p1 & (byte) 0x80) != 0) {
            if ((p1 & (byte) 0x60) != 0) {
                ISOException.throwIt(SW_WRONG_P1P2);
            }
            byte sfi = (byte) (p1 & 0x1F);
            targetEf = mapSfiToFid(sfi);
            if (targetEf == (short) 0x0000) {
                ISOException.throwIt(SW_FILE_NOT_FOUND);
            }
            offset = (short) (p2 & 0x00FF);
        } else {
            offset = (short) (((short) (p1 & 0x7F) << 8) | (short) (p2 & 0x00FF));
        }

        if (targetEf == (short) 0x0000) {
            ISOException.throwIt(SW_FILE_NOT_FOUND);
        }

        byte[] fileData = getEfData(targetEf);

        if (ENFORCE_DG1_READ_POLICY && targetEf == EF_DG1_FID) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (offset < 0 || offset > fileData.length) {
            ISOException.throwIt(SW_OFFSET_INVALID);
        }

        short remaining = (short) (fileData.length - offset);
        short le = apdu.setOutgoing();
        if (le == 0) {
            le = (short) 256;
        }

        if (le > remaining) {
            le = remaining;
        }
        if (le > (short) 255) {
            le = (short) 255;
        }

        apdu.setOutgoingLength((byte) le);
        apdu.sendBytesLong(fileData, offset, (byte) le);
    }

    private short mapSfiToFid(byte sfi) {
        if (sfi == SFI_COM) {
            return EF_COM_FID;
        }
        if (sfi == SFI_DG1) {
            return EF_DG1_FID;
        }
        return (short) 0x0000;
    }

    private byte[] getEfData(short fid) {
        if (fid == EF_COM_FID) {
            return efCom;
        }
        if (fid == EF_DG1_FID) {
            return efDg1;
        }
        ISOException.throwIt(SW_FILE_NOT_FOUND);
        return null;
    }

}
