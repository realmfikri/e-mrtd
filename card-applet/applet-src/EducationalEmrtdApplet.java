package cardapplet;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
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
    private static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    private static final byte INS_CREATE_FILE = (byte) 0xE0;

    private static final short SW_FILE_NOT_FOUND = (short) 0x6A82;
    private static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;
    private static final short SW_WRONG_LENGTH = (short) 0x6700;
    private static final short SW_WRONG_P1P2 = (short) 0x6A86;
    private static final short SW_OFFSET_INVALID = (short) 0x6B00;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;
    private static final short SW_INCORRECT_DATA = (short) 0x6A80;
    private static final short SW_FUNC_NOT_SUPPORTED = (short) 0x6A81;
    private static final short SW_FILE_FULL = (short) 0x6A84;

    private static final short EF_COM_FID = (short) 0x011E;
    private static final short EF_DG1_FID = (short) 0x0101;

    // Demo-only short file identifiers for READ BINARY SFI mode.
    private static final byte SFI_COM = (byte) 0x1E;
    private static final byte SFI_DG1 = (byte) 0x01;

    // Flip to true to demonstrate 6982 on DG1 reads when access control is not implemented.
    private static final boolean ENFORCE_DG1_READ_POLICY = false;

    // Fixed node limits keep filesystem behavior explicit for this educational applet.
    private static final byte MAX_FS_NODES = (byte) 8;
    private static final byte MAX_CHILDREN_PER_DF = (byte) 6;
    // Allow DG2-scale demo payloads (for example ~24KB JPEG) while still bounding EF size.
    private static final short MAX_DYNAMIC_EF_SIZE = (short) 24576;
    private static final byte FDB_TRANSPARENT_EF = (byte) 0x01;
    private static final byte FDB_DF = (byte) 0x38;

    // Persistent demo data.
    private final byte[] efCom = {
        0x54, 0x45, 0x53, 0x54, 0x20, 0x4F, 0x4E, 0x4C, 0x59, 0x20, 0x45, 0x46,
        0x5F, 0x43, 0x4F, 0x4D, 0x0A, 0x46, 0x49, 0x43, 0x54, 0x49, 0x4F, 0x4E,
        0x41, 0x4C, 0x20, 0x44, 0x45, 0x4D, 0x4F, 0x20, 0x4C, 0x44, 0x53, 0x0A
    };

    private final byte[] efDg1 = {
        'T', 'E', 'S', 'T', ' ', 'O', 'N', 'L', 'Y', ' ', 'D', 'G', '1', '\n',
        'N', 'A', 'M', 'E', ':', ' ', 'M', 'U', 'H', 'A', 'M', 'A', 'D', ' ', 'F', 'I', 'K', 'R', 'I', '\n',
        'D', 'O', 'B', ':', ' ', '1', '1', ' ', 'F', 'E', 'B', 'R', 'U', 'A', 'R', 'I', ' ', '2', '0', '0', '3', '\n',
        'S', 'E', 'X', ':', ' ', 'M', 'A', 'L', 'E', '\n',
        'I', 'S', 'S', 'U', 'I', 'N', 'G', ' ', 'S', 'T', 'A', 'T', 'E', '/', 'N', 'A', 'T', 'I', 'O', 'N', 'A', 'L', 'I', 'T', 'Y', ':', ' ', 'I', 'D', 'N', '\n',
        'P', 'A', 'S', 'S', 'P', 'O', 'R', 'T', ' ', 'N', 'O', ':', ' ', 'C', '4', 'X', '9', 'L', '2', 'Q', '7', '\n',
        'E', 'X', 'P', 'I', 'R', 'Y', ' ', 'D', 'A', 'T', 'E', ':', ' ', '1', '1', ' ', 'F', 'E', 'B', 'R', 'U', 'A', 'R', 'I', ' ', '2', '0', '2', '8', '\n'
    };

    private final CardFileSystem fileSystem;
    private FsNode selectedFile;
    private DfNode currentDf;

    private EducationalEmrtdApplet() {
        fileSystem = new CardFileSystem(MAX_FS_NODES, MAX_CHILDREN_PER_DF, efCom, efDg1);
        currentDf = fileSystem.getRoot();
        selectedFile = currentDf;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EducationalEmrtdApplet();
    }

    @Override
    public boolean select() {
        // Reset filesystem cursor whenever the applet is selected by the JCRE.
        currentDf = fileSystem.getRoot();
        selectedFile = currentDf;
        return true;
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
            case INS_UPDATE_BINARY:
                processUpdateBinary(apdu, buffer);
                return;
            case INS_CREATE_FILE:
                processCreateFile(apdu, buffer);
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
        // Applet.getAID() is not available on all Java Card API variants; use JCSystem.getAID().
        AID thisAid = JCSystem.getAID();
        if (!thisAid.partialEquals(buffer, ISO7816.OFFSET_CDATA, (byte) lc)) {
            ISOException.throwIt(SW_FILE_NOT_FOUND);
        }

        currentDf = fileSystem.getRoot();
        selectedFile = currentDf;
    }

    private void selectByFid(short fid) {
        FsNode target;

        if (fid == CardFileSystem.MF_FID) {
            target = fileSystem.getRoot();
        } else if (currentDf != null && currentDf.fid == fid) {
            // Allow re-selecting the current DF by its own FID.
            target = currentDf;
        } else {
            target = fileSystem.findChildByFid(currentDf, fid);
        }

        if (target == null) {
            ISOException.throwIt(SW_FILE_NOT_FOUND);
        }

        selectedFile = target;
        if (target.nodeType != FsNode.TYPE_EF) {
            currentDf = (DfNode) target;
            return;
        }

        currentDf = target.parent;
    }

    private void processReadBinary(APDU apdu, byte[] buffer) {
        short offset;
        EfNode targetEf = null;

        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if ((p1 & (byte) 0x80) != 0) {
            if ((p1 & (byte) 0x60) != 0) {
                ISOException.throwIt(SW_WRONG_P1P2);
            }
            byte sfi = (byte) (p1 & 0x1F);
            short fid = mapSfiToFid(sfi);
            if (fid == (short) 0x0000) {
                ISOException.throwIt(SW_FILE_NOT_FOUND);
            }
            targetEf = fileSystem.findEfByFid(fid);
            if (targetEf == null) {
                ISOException.throwIt(SW_FILE_NOT_FOUND);
            }
            offset = (short) (p2 & 0x00FF);
        } else {
            offset = (short) (((short) (p1 & 0x7F) << 8) | (short) (p2 & 0x00FF));
            if (selectedFile == null || selectedFile.nodeType != FsNode.TYPE_EF) {
                ISOException.throwIt(SW_WRONG_P1P2);
            }
            targetEf = (EfNode) selectedFile;
        }

        byte[] fileData = targetEf.content;

        if (ENFORCE_DG1_READ_POLICY && targetEf.fid == EF_DG1_FID) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (offset < 0 || offset > targetEf.currentLength) {
            ISOException.throwIt(SW_OFFSET_INVALID);
        }

        short remaining = (short) (targetEf.currentLength - offset);
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

    private void processUpdateBinary(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();

        if (selectedFile == null || selectedFile.nodeType != FsNode.TYPE_EF) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        EfNode targetEf = (EfNode) selectedFile;
        if (!targetEf.writable) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }
        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        short offset = (short) (((short) (buffer[ISO7816.OFFSET_P1] & 0x00FF) << 8)
            | (short) (buffer[ISO7816.OFFSET_P2] & 0x00FF));
        if (offset < 0 || offset > targetEf.maxLength) {
            ISOException.throwIt(SW_OFFSET_INVALID);
        }

        short writeEnd = (short) (offset + lc);
        if (writeEnd < offset || writeEnd > targetEf.maxLength) {
            ISOException.throwIt(SW_OFFSET_INVALID);
        }

        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, targetEf.content, offset, lc);
        if (writeEnd > targetEf.currentLength) {
            targetEf.currentLength = writeEnd;
        }
    }

    private void processCreateFile(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if (p1 != (byte) 0x00 || p2 != (byte) 0x00) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        if (lc <= 0) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        short parseOffset = ISO7816.OFFSET_CDATA;
        short end = (short) (parseOffset + lc);
        short fid = (short) 0x0000;
        byte descriptor = (byte) 0x00;
        short efSize = (short) 0;
        boolean sawFid = false;
        boolean sawDescriptor = false;

        while (parseOffset < end) {
            byte tag = buffer[parseOffset++];
            if (parseOffset >= end) {
                ISOException.throwIt(SW_INCORRECT_DATA);
            }

            short len = (short) (buffer[parseOffset++] & 0x00FF);
            if ((short) (parseOffset + len) > end) {
                ISOException.throwIt(SW_INCORRECT_DATA);
            }

            if (tag == (byte) 0x83) {
                if (len != (short) 2) {
                    ISOException.throwIt(SW_INCORRECT_DATA);
                }
                fid = Util.makeShort(buffer[parseOffset], buffer[(short) (parseOffset + 1)]);
                sawFid = true;
            } else if (tag == (byte) 0x82) {
                if (len != (short) 1) {
                    ISOException.throwIt(SW_INCORRECT_DATA);
                }
                descriptor = buffer[parseOffset];
                sawDescriptor = true;
            } else if (tag == (byte) 0x80) {
                if (len == (short) 1) {
                    efSize = (short) (buffer[parseOffset] & 0x00FF);
                } else if (len == (short) 2) {
                    efSize = Util.makeShort(buffer[parseOffset], buffer[(short) (parseOffset + 1)]);
                } else {
                    ISOException.throwIt(SW_INCORRECT_DATA);
                }
            } else {
                ISOException.throwIt(SW_INCORRECT_DATA);
            }

            parseOffset += len;
        }

        if (!sawFid || !sawDescriptor) {
            ISOException.throwIt(SW_INCORRECT_DATA);
        }

        if (descriptor == FDB_DF) {
            if (selectedFile != fileSystem.getRoot()) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            DfNode newDf = fileSystem.createDf(fileSystem.getRoot(), fid);
            currentDf = newDf;
            selectedFile = newDf;
            return;
        }
        if (descriptor == FDB_TRANSPARENT_EF) {
            if (selectedFile == null || selectedFile.nodeType != FsNode.TYPE_DF || selectedFile == fileSystem.getRoot()) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            DfNode parent = (DfNode) selectedFile;
            EfNode newEf = fileSystem.createTransparentEf(parent, fid, efSize);
            selectedFile = newEf;
            return;
        }

        ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
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

    private static class FsNode {
        static final byte TYPE_MF = (byte) 0x01;
        static final byte TYPE_DF = (byte) 0x02;
        static final byte TYPE_EF = (byte) 0x04;

        final byte nodeType;
        final short fid;
        final DfNode parent;

        FsNode(byte nodeType, short fid, DfNode parent) {
            this.nodeType = nodeType;
            this.fid = fid;
            this.parent = parent;
        }
    }

    private static final class DfNode extends FsNode {
        final FsNode[] children;
        byte childCount;

        DfNode(byte nodeType, short fid, DfNode parent, byte maxChildren) {
            super(nodeType, fid, parent);
            children = new FsNode[maxChildren];
            childCount = (byte) 0;
        }
    }

    private static final class EfNode extends FsNode {
        final byte[] content;
        short currentLength;
        final short maxLength;
        final boolean writable;

        EfNode(short fid, DfNode parent, byte[] content, short currentLength, short maxLength, boolean writable) {
            super(TYPE_EF, fid, parent);
            this.content = content;
            this.currentLength = currentLength;
            this.maxLength = maxLength;
            this.writable = writable;
        }
    }

    private static final class CardFileSystem {
        static final short MF_FID = (short) 0x3F00;

        private final FsNode[] allNodes;
        private byte nodeCount;
        private final DfNode root;

        CardFileSystem(byte maxNodes, byte maxChildrenPerDf, byte[] efComData, byte[] efDg1Data) {
            allNodes = new FsNode[maxNodes];
            nodeCount = (byte) 0;

            root = new DfNode(FsNode.TYPE_MF, MF_FID, null, maxChildrenPerDf);
            registerNode(root);

            // Simpler demo semantics: enforce FID uniqueness globally.
            // This is stricter than per-DF uniqueness and avoids path ambiguity in this applet.
            addChild(root, new EfNode(EF_COM_FID, root, efComData, (short) efComData.length, (short) efComData.length, false));
            addChild(root, new EfNode(EF_DG1_FID, root, efDg1Data, (short) efDg1Data.length, (short) efDg1Data.length, false));
        }

        DfNode getRoot() {
            return root;
        }

        FsNode findChildByFid(DfNode parent, short fid) {
            byte i = (byte) 0;
            while (i < parent.childCount) {
                FsNode child = parent.children[i];
                if (child.fid == fid) {
                    return child;
                }
                i++;
            }
            return null;
        }

        EfNode findEfByFid(short fid) {
            FsNode node = findByFid(fid);
            if (node == null || node.nodeType != FsNode.TYPE_EF) {
                return null;
            }
            return (EfNode) node;
        }

        DfNode createDf(DfNode parent, short fid) {
            DfNode created = new DfNode(FsNode.TYPE_DF, fid, parent, MAX_CHILDREN_PER_DF);
            addChild(parent, created);
            return created;
        }

        EfNode createTransparentEf(DfNode parent, short fid, short size) {
            if (size <= 0) {
                ISOException.throwIt(SW_INCORRECT_DATA);
            }
            if (size > MAX_DYNAMIC_EF_SIZE) {
                ISOException.throwIt(SW_FILE_FULL);
            }

            byte[] data;
            try {
                data = new byte[size];
            } catch (SystemException e) {
                ISOException.throwIt(SW_FILE_FULL);
                return null;
            }
            EfNode created = new EfNode(fid, parent, data, size, size, true);
            addChild(parent, created);
            return created;
        }

        private FsNode findByFid(short fid) {
            byte i = (byte) 0;
            while (i < nodeCount) {
                FsNode node = allNodes[i];
                if (node.fid == fid) {
                    return node;
                }
                i++;
            }
            return null;
        }

        private void addChild(DfNode parent, FsNode child) {
            if (findByFid(child.fid) != null) {
                ISOException.throwIt(SW_INCORRECT_DATA);
            }
            if (parent.childCount >= parent.children.length) {
                ISOException.throwIt(SW_FILE_FULL);
            }

            parent.children[parent.childCount] = child;
            parent.childCount++;
            registerNode(child);
        }

        private void registerNode(FsNode node) {
            if (nodeCount >= allNodes.length) {
                ISOException.throwIt(SW_FILE_FULL);
            }
            allNodes[nodeCount] = node;
            nodeCount++;
        }
    }

}
