import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import jdk.internal.jimage.ImageLocation;
import jdk.internal.jimage.ImageReader;

/**
 * Lists a jimage with the JDK's own reader (java.base
 * {@code jdk.internal.jimage.ImageReader}) in the given byte order: for
 * every location its name, content offset, stored and uncompressed size,
 * and the SHA-256 of the resource as the reader returns it (decompressed).
 *
 * <p>Usage: {@code java --add-exports java.base/jdk.internal.jimage=ALL-UNNAMED
 * DumpImage.java <image> <little|big>}.
 */
public final class DumpImage {
    private DumpImage() {
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        ByteOrder order = args[1].equals("big") ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        try (ImageReader reader = ImageReader.open(Path.of(args[0]), order)) {
            for (String name : reader.getEntryNames()) {
                ImageLocation location = reader.findLocation(name);
                byte[] bytes = reader.getResource(location);
                System.out.printf("%s offset=%d stored=%d uncompressed=%d sha256=%s%n",
                        name,
                        location.getContentOffset(),
                        location.getCompressedSize(),
                        location.getUncompressedSize(),
                        HexFormat.of().formatHex(sha256.digest(bytes)));
            }
        }
    }
}
