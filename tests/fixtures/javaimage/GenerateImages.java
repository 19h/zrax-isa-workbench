import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jdk.tools.jlink.builder.ImageBuilder;
import jdk.tools.jlink.internal.Archive;
import jdk.tools.jlink.internal.DirArchive;
import jdk.tools.jlink.internal.ExecutableImage;
import jdk.tools.jlink.internal.ImageFileCreator;
import jdk.tools.jlink.internal.ImagePluginStack;
import jdk.tools.jlink.internal.plugins.DefaultCompressPlugin;
import jdk.tools.jlink.plugin.Plugin;
import jdk.tools.jlink.plugin.ResourcePool;

/**
 * Writes the Zrax jimage fixtures with the JDK's own jimage writer
 * (jdk.jlink {@code ImageFileCreator}, {@code BasicImageWriter} and the
 * {@code --compress} plugin), from one exploded module and without
 * java.base, so the images hold only synthetic content.
 *
 * <p>Usage: {@code java --add-modules jdk.jlink --add-exports ...
 * GenerateImages.java <module-dir> <module-name> <out-dir>}; see
 * generate.sh.
 */
public final class GenerateImages {
    private GenerateImages() {
    }

    public static void main(String[] args) throws IOException {
        Path moduleDir = Path.of(args[0]);
        String moduleName = args[1];
        Path outDir = Path.of(args[2]);
        write(moduleDir, moduleName, outDir.resolve("sample-le.jimage"), ByteOrder.LITTLE_ENDIAN, null);
        write(moduleDir, moduleName, outDir.resolve("sample-be.jimage"), ByteOrder.BIG_ENDIAN, null);
        write(moduleDir, moduleName, outDir.resolve("sample-zip.jimage"), ByteOrder.LITTLE_ENDIAN, "zip-6");
        write(moduleDir, moduleName, outDir.resolve("sample-compact-cp.jimage"), ByteOrder.LITTLE_ENDIAN, "1");
    }

    /** One image in {@code order}, compressed as jlink {@code --compress=<level>} when level is set. */
    private static void write(Path moduleDir, String moduleName, Path out, ByteOrder order, String level)
            throws IOException {
        List<Plugin> plugins = new ArrayList<>();
        if (level != null) {
            DefaultCompressPlugin compress = new DefaultCompressPlugin();
            compress.configure(Map.of("compress", level));
            plugins.add(compress);
        }
        // No resource pool validation: the module's java.base dependency is deliberately absent.
        ImagePluginStack stack = new ImagePluginStack(new FileBuilder(out), plugins, null, false);
        Set<Archive> archives = Set.of(new DirArchive(moduleDir, moduleName));
        ImageFileCreator.create(archives, order, stack);
    }

    /** An image builder that writes the jimage to one file and nothing else. */
    private static final class FileBuilder implements ImageBuilder {
        private final Path out;

        FileBuilder(Path out) {
            this.out = out;
        }

        @Override
        public DataOutputStream getJImageOutputStream() {
            try {
                return new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(out)));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public void storeFiles(ResourcePool content) {
            // A runtime image would also hold launchers and native libraries; the fixtures are the jimage only.
        }

        @Override
        public ExecutableImage getExecutableImage() {
            return null;
        }
    }
}
