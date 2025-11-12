package com.example;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.border.CompoundBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.imageio.ImageIO;

public class UniversalPassportUI extends JFrame {

    // ====== NAV (CardLayout) ======
    private final CardLayout cards = new CardLayout();
    private final JPanel root = new JPanel(cards);

    // ====== Page 1: Form ======
    private JTextField tfDoc, tfDob, tfExp;
    private JButton btnScan;

    // ====== Page 2: Result ======
    private JLabel lblPhoto;
    private JLabel vDoc, vName, vNationality, vDob, vExp, vImageMime, vImageSize;
    private JTextArea taMRZ;
    private JButton btnBack, btnDownloadRaw;
    private JTabbedPane stepTabs;
    private PassportData lastPassport;

    public UniversalPassportUI() {
        super("ePassport Login Page");

        // 1) scale semua default font LAF (komponen yang dibuat SETELAH ini ikut besar)
        scaleUIDefaults(1.90f); // ~50% lebih besar

        // Window configuration
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1280, 800);
        setMinimumSize(new Dimension(960, 600));
        setLocationRelativeTo(null);

        root.add(buildFormPage(), "form");
        root.add(buildResultPage(), "result");
        setContentPane(root);

        // 2) bump font seluruh komponen yang SUDAH ada
        bumpFonts(root, 1.90f); // tambah ~40%

        cards.show(root, "form");
    }

    // ====== Page 1 (Form) ======
    private JPanel buildFormPage() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(24, 32, 24, 32));
        p.setBackground(Color.WHITE);

        var title = new JLabel("ePassport Login Page", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 28));
        title.setBorder(new EmptyBorder(8, 0, 24, 0));
        p.add(title, BorderLayout.NORTH);

        // form grid
        var form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        var gc = new GridBagConstraints();
        gc.insets = new Insets(10, 10, 10, 10);
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL;

        tfDoc = new JTextField(20);
        tfDob = new JTextField(20);
        tfExp = new JTextField(20);

        int r = 0;
        addRow(form, gc, r++, "Nomor Dokumen (Document Number):", tfDoc);
        addRow(form, gc, r++, "Tanggal Lahir (Date of Birth) [YYMMDD]:", tfDob);
        addRow(form, gc, r++, "Tanggal Kadaluarsa (Date of Expiry) [YYMMDD]:", tfExp);

        btnScan = new JButton("Scan ePassport");
        btnScan.setFont(new Font("Segoe UI", Font.BOLD, 16));
        btnScan.addActionListener(e -> startScan());
        gc.gridx = 1; gc.gridy = r++;
        gc.weightx = 0; gc.fill = GridBagConstraints.NONE;
        form.add(btnScan, gc);

        p.add(form, BorderLayout.CENTER);
        return p;
    }

    private static void addRow(JPanel form, GridBagConstraints gc, int row, String label, JComponent field) {
        var l = new JLabel(label);
        l.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        field.setFont(new Font("Segoe UI", Font.PLAIN, 16));

        gc.gridx = 0; gc.gridy = row; gc.weightx = 0.0; gc.fill = GridBagConstraints.NONE;
        form.add(l, gc);
        gc.gridx = 1; gc.gridy = row; gc.weightx = 1.0; gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(field, gc);
    }

    // ====== Page 2 (Result) ======
    private JPanel buildResultPage() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(24, 32, 24, 32));
        p.setBackground(Color.WHITE);

        var title = new JLabel("ePassport Result", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 28));
        title.setBorder(new EmptyBorder(8, 0, 24, 0));
        p.add(title, BorderLayout.NORTH);

        // ===== Summary row (photo + decoded fields) =====
        lblPhoto = new JLabel("No Photo", SwingConstants.CENTER);
        lblPhoto.setPreferredSize(new Dimension(360, 480));
        lblPhoto.setBorder(BorderFactory.createLineBorder(Color.GRAY));

        var dataPanel = new JPanel(new GridBagLayout());
        dataPanel.setOpaque(false);
        var g2 = new GridBagConstraints();
        g2.insets = new Insets(6, 6, 6, 6);
        g2.anchor = GridBagConstraints.WEST;
        g2.fill = GridBagConstraints.HORIZONTAL;

        vDoc = addKV(dataPanel, g2, 0, "Document Number:");
        vName = addKV(dataPanel, g2, 1, "Full Name:");
        vNationality = addKV(dataPanel, g2, 2, "Nationality:");
        vDob = addKV(dataPanel, g2, 3, "Date of Birth (YYMMDD):");
        vExp = addKV(dataPanel, g2, 4, "Date of Expiry (YYMMDD):");
        /*
        vImageMime = addKV(dataPanel, g2, 5, "Image MIME:");
        vImageSize = addKV(dataPanel, g2, 6, "Image Size:");
        */

        var photoHolder = new JPanel(new BorderLayout());
        photoHolder.setOpaque(false);
        photoHolder.add(lblPhoto, BorderLayout.CENTER);

        var photoBox = wrapWithTitledBox("Photograph", photoHolder);
        photoBox.setAlignmentY(Component.TOP_ALIGNMENT);
        photoBox.setMaximumSize(new Dimension(420, Integer.MAX_VALUE));

        var dataBox = wrapWithTitledBox("Decoded Fields", dataPanel);
        dataBox.setAlignmentY(Component.TOP_ALIGNMENT);

        var summaryRow = new JPanel();
        summaryRow.setOpaque(false);
        summaryRow.setLayout(new BoxLayout(summaryRow, BoxLayout.X_AXIS));
        summaryRow.add(photoBox);
        summaryRow.add(Box.createHorizontalStrut(16));
        summaryRow.add(dataBox);
        summaryRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        taMRZ = new JTextArea(4, 60);
        taMRZ.setLineWrap(true);
        taMRZ.setWrapStyleWord(true);
        taMRZ.setEditable(false);
        taMRZ.setFont(new Font("Monospaced", Font.PLAIN, 16));
        taMRZ.setText("-");
        var rawScroll = new JScrollPane(taMRZ);
        rawScroll.setBorder(BorderFactory.createEmptyBorder());
        var rawBox = wrapWithTitledBox("Raw MRZ (DG1)", rawScroll);
        rawBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        // ===== Pipeline tabs =====
        stepTabs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        stepTabs.setFont(new Font("Segoe UI", Font.BOLD, 18));
        stepTabs.addTab("Pipeline", wrapStepPanel(createPlaceholderPanel("Scan an ePassport to see each processing step.")));

        var pipelineBox = wrapWithTitledBox("Processing Steps", stepTabs);
        pipelineBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        // ===== Main content (summary on top, pipeline below) =====
        var content = new JPanel();
        content.setOpaque(false);
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(summaryRow);
        content.add(Box.createVerticalStrut(16));
        content.add(rawBox);
        content.add(Box.createVerticalStrut(16));
        content.add(pipelineBox);
        content.add(Box.createVerticalGlue());

        var contentScroll = new JScrollPane(content);
        contentScroll.setBorder(BorderFactory.createEmptyBorder());
        contentScroll.setOpaque(false);
        contentScroll.getViewport().setOpaque(false);
        contentScroll.getVerticalScrollBar().setUnitIncrement(18);

        p.add(contentScroll, BorderLayout.CENTER);

        // Bottom bar
        var bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 4));
        btnDownloadRaw = new JButton("Download Raw Data");
        btnDownloadRaw.addActionListener(e -> downloadRawData());
        btnBack = new JButton("Back");
        btnBack.addActionListener(e -> cards.show(root, "form"));
        bottom.add(btnDownloadRaw);
        bottom.add(btnBack);
        p.add(bottom, BorderLayout.SOUTH);

        return p;
    }

    private static JLabel addKV(JPanel panel, GridBagConstraints g2, int row, String key) {
        var lk = new JLabel(key);
        lk.setFont(new Font("Segoe UI", Font.BOLD, 18));
        var lv = new JLabel("-");
        lv.setFont(new Font("Segoe UI", Font.PLAIN, 18));

        g2.gridx = 0; g2.gridy = row; g2.weightx = 0;
        panel.add(lk, g2);
        g2.gridx = 1; g2.gridy = row; g2.weightx = 1;
        panel.add(lv, g2);
        return lv;
    }

    private JPanel createPlaceholderPanel(String message) {
        var panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);
        var label = new JLabel("<html><div style='text-align:center;'>" + message + "</div></html>", SwingConstants.CENTER);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 18));
        panel.add(label, BorderLayout.CENTER);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        return panel;
    }

    private Component wrapStepPanel(JPanel content) {
        var scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        return scroll;
    }

    private JPanel createStepPanel(String inputs, String process, String outputs, String nextStep) {
        var panel = new JPanel();
        panel.setOpaque(false);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(16, 24, 16, 24));

        panel.add(createBlock("Inputs", inputs));
        panel.add(Box.createVerticalStrut(12));
        panel.add(createBlock("Process", process));
        panel.add(Box.createVerticalStrut(12));
        panel.add(createBlock("Outputs", outputs));
        if (nextStep != null && !nextStep.isBlank()) {
            panel.add(Box.createVerticalStrut(12));
            panel.add(createBlock("Next Step", nextStep));
        }
        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private JComponent createBlock(String title, String content) {
        var wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(new Color(249, 249, 249));
        wrapper.setOpaque(true);
        wrapper.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 210, 210)),
                new EmptyBorder(8, 12, 8, 12)
        ));

        var lbl = new JLabel(title);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 16));
        wrapper.add(lbl, BorderLayout.NORTH);

        var area = new JTextArea((content == null || content.isBlank()) ? "-" : content);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setEditable(false);
        area.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        area.setOpaque(false);
        area.setBorder(null);
        wrapper.add(area, BorderLayout.CENTER);
        return wrapper;
    }

    private JComponent wrapWithTitledBox(String title, JComponent inner) {
        var wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        var titleBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(210, 210, 210)),
                title,
                TitledBorder.LEADING,
                TitledBorder.TOP,
                new Font("Segoe UI", Font.BOLD, 16),
                Color.DARK_GRAY
        );
        wrapper.setBorder(new CompoundBorder(titleBorder, new EmptyBorder(12, 12, 12, 12)));
        wrapper.add(inner, BorderLayout.CENTER);
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        return wrapper;
    }

    // ====== Actions ======
    private void startScan() {
        btnScan.setEnabled(false);

        final String doc = normDoc(tfDoc.getText());
        final String dob = normDate6(tfDob.getText());
        final String exp = normDate6(tfExp.getText());

        // Validasi simple
        if (doc.length() != 9 || dob.length() != 6 || exp.length() != 6) {
            JOptionPane.showMessageDialog(this,
                    "Input tidak valid.\nNomor Dokumen harus 8-9 karakter.\nDate of Birth dan Date of Expiry harus YYMMDD.",
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
            btnScan.setEnabled(true);
            return;
        }

        // Background thread supaya UI nggak freeze
        new Thread(() -> {
            try {
                PassportData data = UniversalPassportReader.readPassport(doc, dob, exp);
                SwingUtilities.invokeLater(() -> showResult(data));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this,
                            "Paspor tidak terbaca / data tidak valid.\n" +
                            "Cek reader, paspor menempel, dan input MRZ.\n\n" +
                            "[" + ex.getClass().getSimpleName() + "] " + ex.getMessage(),
                            "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                    btnScan.setEnabled(true);
                });
            }
        }, "scan-thread").start();
    }

    // ===== gantikan isi showResult(...) kamu dengan ini =====
    private void showResult(PassportData p) {
        lastPassport = p;
        vDoc.setText(formatDoc(p.documentNumber()));
        vName.setText(formatNameComma(p.fullName()));
        vNationality.setText(countryName(p.nationality()));
        vDob.setText(nullToDash(p.dateOfBirth()));
        vExp.setText(nullToDash(p.dateOfExpiry()));
        //vImageMime.setText(nullToDash(p.imageMime()));
        //vImageSize.setText(p.imageBytes() == null ? "-" : (p.imageBytes().length + " bytes"));
        setRawMrz(p.mrz());

        setPhoto(p.imageBytes(), p.imageMime());
        updateStepTabs(p);
        cards.show(root, "result");
        btnScan.setEnabled(true);
    }

    private void updateStepTabs(PassportData p) {
        if (stepTabs == null) return;

        String doc = formatDoc(p.documentNumber());
        String dob = nullToDash(p.dateOfBirth());
        String exp = nullToDash(p.dateOfExpiry());
        String rawName = nullToDash(p.fullName());
        String formattedName = formatNameComma(p.fullName());
        String nationalityCode = nullToDash(p.nationality());
        String nationalityFriendly = countryName(p.nationality());
        String mrzDisplay = formatMrzForDisplay(p.mrz());
        String imageMime = nullToDash(p.imageMime());
        String imageSize = (p.imageBytes() == null || p.imageBytes().length == 0)
                ? "-"
                : p.imageBytes().length + " bytes";

        String step1Inputs = String.format(
                "Document Number: %s%nDate of Birth: %s%nDate of Expiry: %s",
                doc, dob, exp
        );
        String step1Process = "Derive BAC keys from the operator inputs, open a secure session, and request DG1 (MRZ) plus DG2 (face image) from the chip.";
        String step1Outputs = String.format(
                "MRZ (DG1):%n%s%n%nFace image payload (DG2): %s (%s)",
                mrzDisplay,
                imageSize,
                imageMime
        );

        String step2Inputs = "Raw MRZ text from Step 1:\n" + mrzDisplay;
        String step2Process = "Split MRZ lines, remove filler characters, and decode each field according to ICAO 9303.";
        String step2Outputs = String.format(
                "Document Number: %s%nName (raw MRZ): %s%nNationality Code: %s%nDate of Birth: %s%nDate of Expiry: %s",
                doc, rawName, nationalityCode, dob, exp
        );

        String step3Inputs = String.format(
                "Parsed fields -> doc: %s, name: %s, nationality: %s, DOB: %s, EXP: %s",
                doc, rawName, nationalityCode, dob, exp
        );
        String step3Process = "Normalize casing, map country codes to friendly names, and bind the values to the summary table.";
        String step3Outputs = String.format(
                "Display Name: %s%nNationality: %s%nDocument Number: %s%nBirth Date: %s%nExpiry Date: %s",
                formattedName, nationalityFriendly, doc, dob, exp
        );

        String step4Inputs = String.format(
                "Image MIME: %s%nPayload Size: %s",
                imageMime, imageSize
        );
        String step4Process = "Decode the DG2 bytes (JPEG/JPEG2000), scale the BufferedImage to the placeholder, and render it for manual verification.";
        String step4Outputs = (p.imageBytes() == null || p.imageBytes().length == 0)
                ? "No image available; UI keeps the \"No Photo\" placeholder."
                : "Photo decoded successfully and displayed on the left preview.";
        String finalNext = "Result screen is ready; verify visually or hit \"Download Raw Data\" to export DG1/DG2 blobs untouched.";

        stepTabs.removeAll();
        stepTabs.addTab("Step 1 - Raw Data", wrapStepPanel(createStepPanel(step1Inputs, step1Process, step1Outputs, "Step 2 - Parse MRZ")));
        stepTabs.addTab("Step 2 - Parse MRZ", wrapStepPanel(createStepPanel(step2Inputs, step2Process, step2Outputs, "Step 3 - Identity Profile")));
        stepTabs.addTab("Step 3 - Identity Profile", wrapStepPanel(createStepPanel(step3Inputs, step3Process, step3Outputs, "Step 4 - Biometrics")));
        stepTabs.addTab("Step 4 - Biometrics", wrapStepPanel(createStepPanel(step4Inputs, step4Process, step4Outputs, finalNext)));
        stepTabs.revalidate();
        stepTabs.repaint();
    }

    // ====== Helpers ======

    // Hapus semua '<' dari nomor dokumen
    private static String formatDoc(String s) {
        if (s == null || s.isBlank()) return "-";
        return s.replace("<", "");
    }

    private static String formatMrzForDisplay(String mrz) {
        if (mrz == null || mrz.isBlank()) return "-";
        String normalized = mrz.replace("\r", "").trim();
        return normalized.isEmpty() ? "-" : normalized;
    }

    private void setRawMrz(String mrz) {
        if (taMRZ == null) return;
        taMRZ.setText((mrz == null || mrz.isBlank()) ? "-" : mrz);
        taMRZ.setCaretPosition(0);
    }

    // Tampilkan nama sebagai "KATA_PERTAMA, sisa_kata"
    private static String formatNameComma(String s) {
        if (s == null) return "-";
        s = s.trim().replaceAll("\\s+", " ");
        if (s.isEmpty()) return "-";
        String[] parts = s.split(" ");
        if (parts.length == 1) return parts[0];
        StringBuilder rest = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            if (i > 1) rest.append(' ');
            rest.append(parts[i]);
        }
        return parts[0] + ", " + rest.toString();
    }

    // Map kode negara MRZ ke nama negara (minimal yang diperlukan)
    private static String countryName(String code) {
        if (code == null || code.isBlank()) return "-";
        String c = code.trim().toUpperCase();
        switch (c) {
            case "IDN": return "INDONESIA";
            case "USA": return "UNITED STATES";
            case "GBR": return "UNITED KINGDOM";
            case "AUS": return "AUSTRALIA";
            case "MYS": return "MALAYSIA";
            case "SGP": return "SINGAPORE";
            // tambahkan bila perlu...
            default:     return c; // fallback: tampilkan kode aslinya
        }
    }

    private void downloadRawData() {
        if (lastPassport == null) {
            JOptionPane.showMessageDialog(this, "Tidak ada data paspor untuk disimpan.", "No Data", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose folder to save raw passport files");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File targetDir = chooser.getSelectedFile();
        if (targetDir == null) return;

        String folderName = "passport_raw_" + System.currentTimeMillis();
        Path base = targetDir.toPath().resolve(folderName);
        try {
            Files.createDirectories(base);
            if (lastPassport.mrz() != null && !lastPassport.mrz().isBlank()) {
                Files.writeString(base.resolve("DG1_MRZ.txt"), lastPassport.mrz(), StandardCharsets.UTF_8);
            }
            byte[] image = lastPassport.imageBytes();
            if (image != null && image.length > 0) {
                String ext = extensionForMime(lastPassport.imageMime());
                Files.write(base.resolve("DG2_Face" + ext), image);
            }
            JOptionPane.showMessageDialog(this,
                    "Raw files saved to:\n" + base.toAbsolutePath(),
                    "Raw Data Saved",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Gagal menyimpan data: " + ex.getMessage(),
                    "Save Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String extensionForMime(String mime) {
        if (mime == null) return ".bin";
        String normalized = mime.toLowerCase();
        if (normalized.contains("jpeg") || normalized.contains("jpg")) return ".jpg";
        if (normalized.contains("jp2")) return ".jp2";
        if (normalized.contains("png")) return ".png";
        if (normalized.contains("wsq")) return ".wsq";
        return ".bin";
    }

    private void setPhoto(byte[] bytes, String mime) {
        if (bytes == null || bytes.length == 0) {
            lblPhoto.setText("No Photo");
            lblPhoto.setIcon(null);
            return;
        }
        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(bytes));
            if (img == null) {
                // Kemungkinan JPEG2000 tanpa codec
                lblPhoto.setText("Image not decodable.\n(Install JPEG2000 codec)");
                lblPhoto.setIcon(null);
                return;
            }
            Image scaled = img.getScaledInstance(lblPhoto.getWidth(), lblPhoto.getHeight(), Image.SCALE_SMOOTH);
            lblPhoto.setIcon(new ImageIcon(scaled));
            lblPhoto.setText("");
        } catch (Exception e) {
            lblPhoto.setText("Error load image: " + e.getMessage());
            lblPhoto.setIcon(null);
        }
    }

    private static String normDoc(String s) {
        if (s == null) return "";
        s = s.trim().toUpperCase().replace(" ", "");
        s = s.replaceAll("[^A-Z0-9<]", "");
        if (s.length() > 9) s = s.substring(0, 9);
        while (s.length() < 9) s = s + "<";
        return s;
    }

    private static String normDate6(String s) {
        if (s == null) return "";
        s = s.trim().replaceAll("\\D", "");
        if (s.length() > 6) s = s.substring(0, 6);
        return s;
    }

    private static String nullToDash(String s) {
        return (s == null || s.isBlank()) ? "-" : s;
    }

    // ====== Global font scalers ======
    // Scale default font UIManager (pengaruhnya ke komponen yang DIBUAT setelah ini)
    private static void scaleUIDefaults(float factor) {
        java.util.Enumeration<Object> keys = UIManager.getDefaults().keys();
        while (keys.hasMoreElements()) {
            Object k = keys.nextElement();
            Object v = UIManager.get(k);
            if (v instanceof Font f) {
                UIManager.put(k, f.deriveFont(f.getSize2D() * factor));
            }
        }
    }

    // Naikkan font semua komponen yang SUDAH ada (rekursif)
    private static void bumpFonts(Component c, float factor) {
        if (c == null) return;
        Font f = c.getFont();
        if (f != null) c.setFont(f.deriveFont(f.getSize2D() * factor));
        if (c instanceof Container cont) {
            for (Component child : cont.getComponents()) bumpFonts(child, factor);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new UniversalPassportUI().setVisible(true));
    }
}
