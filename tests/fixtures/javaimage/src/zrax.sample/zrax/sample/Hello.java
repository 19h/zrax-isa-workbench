package zrax.sample;

import java.util.List;

/**
 * Synthetic class for the Zrax jimage and JMOD fixtures. Its constant pool
 * holds every entry kind the jimage string-sharing (compact-cp) transform
 * rewrites or copies: names, descriptors with object types, a string, an
 * integer, a float, a long, a double, method handles and an invokedynamic
 * call site.
 */
public final class Hello {
    /** A long constant (`CONSTANT_Long`). */
    public static final long SEED = 0x0123_4567_89AB_CDEFL;

    /** A double constant (`CONSTANT_Double`). */
    public static final double SCALE = 1.5e300;

    /** An integer constant outside the short range (`CONSTANT_Integer`). */
    public static final int LIMIT = 100_000;

    /** A float constant (`CONSTANT_Float`). */
    public static final float RATIO = 0.75f;

    private Hello() {
    }

    /** Joins the greeting, the name and the item count. */
    public static String greet(String name, List<Object> items) {
        return "Hello, " + name + ": " + items.size() + " items";
    }
}
