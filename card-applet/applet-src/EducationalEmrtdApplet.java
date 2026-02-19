package cardapplet;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
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

    // Fixed small limits keep memory usage explicit for Java Card-style targets.
    private static final byte MAX_FS_NODES = (byte) 8;
    private static final byte MAX_CHILDREN_PER_DF = (byte) 6;

    // Persistent demo data.
    private final byte[] efCom = {
        0x54, 0x45, 0x53, 0x54, 0x20, 0x4F, 0x4E, 0x4C, 0x59, 0x20, 0x45, 0x46,
        0x5F, 0x43, 0x4F, 0x4D, 0x0A, 0x46, 0x49, 0x43, 0x54, 0x49, 0x4F, 0x4E,
        0x41, 0x4C, 0x20, 0x44, 0x45, 0x4D, 0x4F, 0x20, 0x4C, 0x44, 0x53, 0x0A
    };

    private final byte[] efDg1 = {
        0x54, 0x45, 0x53, 0x54, 0x20, 0x4F, 0x4E, 0x4C, 0x59, 0x20, 0x44, 0x47,
        0x31, 0x0A, 0x46, 0x49, 0x43, 0x54, 0x49, 0x4F, 0x4E, 0x41, 0x4C, 0x20,
        0x48, 0x4F, 0x4C, 0x44, 0x45, 0x52, 0x3A, 0x20, 0x44, 0x4F, 0x45, 0x3C,
        0x3C, 0x41, 0x4C, 0x45, 0x58, 0x0A
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

    private short mapSfiToFid(byte sfi) {
        if (sfi == SFI_COM) {
            return EF_COM_FID;
        }
        if (sfi == SFI_DG1) {
            return EF_DG1_FID;
        }
        return (short) 0x0000;
    }

    private static final class FsNode {
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

        EfNode(short fid, DfNode parent, byte[] content, short currentLength, short maxLength) {
            super(TYPE_EF, fid, parent);
            this.content = content;
            this.currentLength = currentLength;
            this.maxLength = maxLength;
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
            addChild(root, new EfNode(EF_COM_FID, root, efComData, (short) efComData.length, (short) efComData.length));
            addChild(root, new EfNode(EF_DG1_FID, root, efDg1Data, (short) efDg1Data.length, (short) efDg1Data.length));
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
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            if (parent.childCount >= parent.children.length) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }

            parent.children[parent.childCount] = child;
            parent.childCount++;
            registerNode(child);
        }

        private void registerNode(FsNode node) {
            if (nodeCount >= allNodes.length) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            allNodes[nodeCount] = node;
            nodeCount++;
        }
    }

}
