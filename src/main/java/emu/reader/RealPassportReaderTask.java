package emu.reader;

import javafx.concurrent.Task;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.TerminalCardService;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.AccessKeySpec;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;

/**
 * JavaFX {@link Task} implementation that performs a real eMRTD read operation.
 */
public class RealPassportReaderTask extends Task<RealPassportSnapshot> {

    private final TerminalFactory terminalFactory;
    private final int terminalIndex;
    private final String documentNumber;
    private final String dateOfBirth;
    private final String dateOfExpiry;
    private final Consumer<String> logger;

    public RealPassportReaderTask(String documentNumber,
                                  String dateOfBirth,
                                  String dateOfExpiry) {
        this(null, 0, documentNumber, dateOfBirth, dateOfExpiry, null);
    }

    public RealPassportReaderTask(TerminalFactory terminalFactory,
                                  int terminalIndex,
                                  String documentNumber,
                                  String dateOfBirth,
                                  String dateOfExpiry,
                                  Consumer<String> logger) {
        this.terminalFactory = terminalFactory;
        this.terminalIndex = terminalIndex;
        this.documentNumber = Objects.requireNonNull(documentNumber, "documentNumber");
        this.dateOfBirth = Objects.requireNonNull(dateOfBirth, "dateOfBirth");
        this.dateOfExpiry = Objects.requireNonNull(dateOfExpiry, "dateOfExpiry");
        this.logger = logger;
    }

    @Override
    protected RealPassportSnapshot call() throws Exception {
        updateMessage("Preparing security provider...");
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        TerminalFactory factory = terminalFactory != null ? terminalFactory : TerminalFactory.getDefault();
        updateMessage("Locating NFC terminals...");
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals == null || terminals.isEmpty()) {
            throw new IllegalStateException("No NFC terminal found.");
        }

        if (terminalIndex < 0 || terminalIndex >= terminals.size()) {
            throw new IllegalArgumentException("Terminal index " + terminalIndex + " out of range. Found " + terminals.size() + " terminal(s).");
        }

        CardTerminal terminal = terminals.get(terminalIndex);
        updateMessage("Waiting for passport...");
        terminal.waitForCardPresent(0);

        CardService cardService = new TerminalCardService(terminal);
        PassportService service = null;

        try {
            updateMessage("Opening passport service...");
            cardService.open();

            service = new PassportService(cardService, 256, 224, false, false);
            service.open();
            service.sendSelectApplet(false);

            updateMessage("Performing BAC...");
            AccessKeySpec bacKey = new BACKey(documentNumber, dateOfBirth, dateOfExpiry);
            service.doBAC(bacKey);
            service.sendSelectApplet(true);

            final PassportService activeService = service;

            updateMessage("Reading DG1...");
            Map<Integer, byte[]> dataGroups = new HashMap<>();
            MRZInfo mrzInfo;
            String mrzText;
            byte[] dg1Bytes;
            try (InputStream dg1In = activeService.getInputStream(PassportService.EF_DG1)) {
                dg1Bytes = readAllBytes(dg1In);
            }
            dataGroups.put(1, dg1Bytes);
            try (InputStream parsedDg1 = new ByteArrayInputStream(dg1Bytes)) {
                DG1File dg1File = new DG1File(parsedDg1);
                mrzInfo = dg1File.getMRZInfo();
                mrzText = mrzInfo == null ? null : mrzInfo.toString();
            }

            String fullName = "";
            String nationality = "";
            if (mrzInfo != null) {
                String primary = nz(mrzInfo.getPrimaryIdentifier());
                String secondary = nz(mrzInfo.getSecondaryIdentifier());
                fullName = (primary + " " + secondary).trim().replaceAll(" +", " ");
                nationality = nz(mrzInfo.getNationality());
            }

            updateMessage("Reading DG2...");
            byte[] imageBytes = null;
            String imageMime = null;
            byte[] dg2Bytes = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_DG2), this::log, "DG2");
            if (dg2Bytes != null) {
                dataGroups.put(2, dg2Bytes);
                try (InputStream dg2In = new ByteArrayInputStream(dg2Bytes)) {
                    DG2File dg2File = new DG2File(dg2In);
                    if (!dg2File.getFaceInfos().isEmpty()) {
                        FaceInfo face = dg2File.getFaceInfos().get(0);
                        if (!face.getFaceImageInfos().isEmpty()) {
                            FaceImageInfo faceImageInfo = face.getFaceImageInfos().get(0);
                            imageMime = faceImageInfo.getMimeType();
                            try (InputStream imgIn = faceImageInfo.getImageInputStream();
                                 ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                                byte[] tmp = new byte[4096];
                                int read;
                                while ((read = imgIn.read(tmp)) != -1) {
                                    buffer.write(tmp, 0, read);
                                    if (isCancelled()) {
                                        updateMessage("Cancelled");
                                        return null;
                                    }
                                }
                                imageBytes = buffer.toByteArray();
                            }
                        }
                    }
                } catch (Exception e) {
                    log("Unable to parse DG2: " + e.getMessage());
                }
            }

            byte[] comFile = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_COM), this::log, "EF.COM");
            byte[] sodFile = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_SOD), this::log, "EF.SOD");
            byte[] cardAccessFile = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_CARD_ACCESS), this::log, "EF.CardAccess");
            byte[] dg14Bytes = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_DG14), this::log, "DG14");
            byte[] dg15Bytes = readOptionalFile(() -> activeService.getInputStream(PassportService.EF_DG15), this::log, "DG15");
            if (dg14Bytes != null) {
                dataGroups.put(14, dg14Bytes);
            }
            if (dg15Bytes != null) {
                dataGroups.put(15, dg15Bytes);
            }

            updateMessage("Passport read complete");
            return new RealPassportSnapshot(
                    documentNumber,
                    dateOfBirth,
                    dateOfExpiry,
                    mrzText,
                    fullName,
                    nationality,
                    imageMime,
                    imageBytes,
                    dataGroups,
                    comFile,
                    sodFile,
                    cardAccessFile
            );
        } finally {
            updateMessage("Cleaning up...");
            if (service != null) {
                try {
                    service.close();
                } catch (Exception e) {
                    log("Failed to close PassportService: " + e.getMessage());
                }
            }
            try {
                cardService.close();
            } catch (Exception e) {
                log("Failed to close CardService: " + e.getMessage());
            }
        }
    }

    static byte[] readOptionalFile(InputStreamSupplier supplier, Consumer<String> logger, String label) {
        try (InputStream in = supplier.get()) {
            if (in == null) {
                return null;
            }
            return readAllBytes(in);
        } catch (Exception e) {
            if (logger != null) {
                logger.accept("Unable to read " + label + ": " + e.getMessage());
            } else {
                System.err.println("Unable to read " + label + ": " + e.getMessage());
            }
            return null;
        }
    }

    private static byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int read;
        while ((read = in.read(tmp)) != -1) {
            buffer.write(tmp, 0, read);
        }
        return buffer.toByteArray();
    }

    private void log(String message) {
        if (logger != null) {
            logger.accept(message);
        } else {
            System.err.println(message);
        }
    }

    @FunctionalInterface
    interface InputStreamSupplier {
        InputStream get() throws Exception;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}

