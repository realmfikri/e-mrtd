package com.example;

import net.sf.scuba.data.Gender;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/**
 * Utility that wraps a plain JPEG into an ISO/IEC 19794-5 compliant DG2 file.
 * <p>
 * Usage:
 * <pre>
 *   mvn -q exec:java -Dexec.mainClass=com.example.DG2BuilderDemo \
 *       -Dexec.args="passport_raw_1762504342021/DG2_Face.jpg target/generated_dg2.bin"
 * </pre>
 */
public final class DG2BuilderDemo {

    private DG2BuilderDemo() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: DG2BuilderDemo <inputImage> [outputDG2Bin]");
            return;
        }
        Path imagePath = Path.of(args[0]);
        if (!Files.exists(imagePath)) {
            throw new IllegalArgumentException("Input image not found: " + imagePath.toAbsolutePath());
        }
        Path outputPath = args.length > 1 ? Path.of(args[1]) : Path.of("target/generated_dg2.bin");
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        byte[] imageBytes = Files.readAllBytes(imagePath);
        BufferedImage bufferedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (bufferedImage == null) {
            throw new IllegalArgumentException("ImageIO failed to decode " + imagePath + ". Provide a JPEG/JPEG2000 image.");
        }

        byte[] dg2Bytes = buildISO19794DG2(imageBytes, bufferedImage.getWidth(), bufferedImage.getHeight());
        Files.write(outputPath, dg2Bytes);

        System.out.println("DG2 encoded bytes written to: " + outputPath.toAbsolutePath());
        System.out.println("DG2 length         : " + dg2Bytes.length + " bytes");
        System.out.println("Face image (input) : " + imageBytes.length + " bytes, " +
                bufferedImage.getWidth() + "x" + bufferedImage.getHeight());
        System.out.println("DG2 preview        : " + hexdump(dg2Bytes));
    }

    private static byte[] buildISO19794DG2(byte[] imageBytes, int width, int height) throws IOException {
        FaceImageInfo faceImageInfo = new FaceImageInfo(
                Gender.UNSPECIFIED,
                FaceImageInfo.EyeColor.UNSPECIFIED,
                0, // feature mask
                FaceImageInfo.HAIR_COLOR_UNSPECIFIED,
                FaceImageInfo.EXPRESSION_NEUTRAL,
                new int[] {0, 0, 0}, // yaw/pitch/roll
                new int[] {0, 0, 0}, // uncertainties
                FaceImageInfo.FACE_IMAGE_TYPE_FULL_FRONTAL,
                FaceImageInfo.IMAGE_COLOR_SPACE_RGB24,
                FaceImageInfo.SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM,
                0,  // device type
                80, // quality
                new FaceImageInfo.FeaturePoint[0],
                width,
                height,
                new ByteArrayInputStream(imageBytes),
                imageBytes.length,
                FaceImageInfo.IMAGE_DATA_TYPE_JPEG
        );

        FaceInfo faceInfo = new FaceInfo(List.of(faceImageInfo));
        DG2File dg2File = DG2File.createISO19794DG2File(List.of(faceInfo));
        return dg2File.getEncoded();
    }

    private static String hexdump(byte[] data) {
        int previewLength = Math.min(64, data.length);
        byte[] preview = new byte[previewLength];
        System.arraycopy(data, 0, preview, 0, previewLength);
        return HexFormat.of().withUpperCase().formatHex(preview) + (data.length > previewLength ? "..." : "");
    }
}
