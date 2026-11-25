package gov.dot.faa.ang.idms.acmetpm.crypto.bridge;

import module java.base;

import org.slf4j.*;

import gov.dot.faa.ang.idms.acmetpm.PlatformLibraryLoader;

import static java.lang.foreign.ValueLayout.*;

public final class CapiTpmBridge implements TpmCryptoBridge {
    private static final Integer ERROR_BUFFER_SIZE = 1024;
    private static final Logger logger = LoggerFactory.getLogger(CapiTpmBridge.class);

    // Private Constructor to hide implicit
    private CapiTpmBridge() {}

    public static void generateTpmKey(String alias, String container, String subjectDn) throws Throwable {
        if(!System.getProperty("os.name").toLowerCase().contains("win")) {
            throw new UnsupportedOperationException("CAPI key generation only works on windows.");
        }

        var tmpDllPath = PlatformLibraryLoader.loadPlatformLibrary();

        try (var arena = Arena.ofConfined()) {
            var lib = SymbolLookup.libraryLookup(tmpDllPath, arena);
            var generateFunction = Linker.nativeLinker().downcallHandle(
                lib.findOrThrow("generate_tpm_key"), 
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS,ADDRESS,ADDRESS,JAVA_INT)
            );

            MemorySegment aliasSeg = arena.allocateFrom(alias, StandardCharsets.UTF_8);
            MemorySegment containerSeg = arena.allocateFrom(container, StandardCharsets.UTF_8);
            MemorySegment subjectSeg = arena.allocateFrom(subjectDn, StandardCharsets.UTF_8);

            MemorySegment errorBuffer = arena.allocate(ERROR_BUFFER_SIZE);

            int returnCode = (int) generateFunction.invokeExact(aliasSeg, containerSeg, subjectSeg, errorBuffer, ERROR_BUFFER_SIZE.intValue());

            if (returnCode != 0) {
                String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
                throw new IllegalStateException("TPM Key Generation failed (code " + returnCode + "): " + errorDetails);
            } else {
                logger.info("Successfully generated TPM key with alias '{}' in container '{}'", alias, container);
                String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
                if (!errorDetails.isEmpty()) {
                    logger.warn("TPM Key Generation returned warnings: {}", errorDetails);
                }
            }
        } finally {
            try {
                Files.deleteIfExists(tmpDllPath);
            } catch (AccessDeniedException e) {
                logger.warn("Unable to immediately delete temporary native library {}; deletion is deferred to JVM exit", tmpDllPath);
            }
        }
    }
}
