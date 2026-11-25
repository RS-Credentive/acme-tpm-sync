package gov.dot.faa.ang.idms.acmetpm.webserver.iis;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import module java.base;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.PlatformLibraryLoader;
import gov.dot.faa.ang.idms.acmetpm.webserver.IisWebServerBridge;
import gov.dot.faa.ang.idms.acmetpm.webserver.IisWebServerBridge.SiteConfig;

public class IisConfigReader {
    private static final Logger logger = LoggerFactory.getLogger(IisConfigReader.class);

    public List<SiteConfig> readConfig() throws Throwable {
        if(!System.getProperty("os.name").toLowerCase().contains("win")) {
            throw new UnsupportedOperationException("This function can only be called on Windows.");
        }
        
        var tmpDllPath = PlatformLibraryLoader.loadPlatformLibrary();
        logger.info("Reading IIS configuration using native library at {}", tmpDllPath);

        try (var arena = Arena.ofConfined()) {
            var lib = SymbolLookup.libraryLookup(tmpDllPath, arena);

            // This function builds the configuration buffer and returns its size. If it returns -1, an error occurred.
            var configBufferSizeFunction = Linker.nativeLinker().downcallHandle(
                lib.findOrThrow("get_binding_buffer_size"), 
                FunctionDescriptor.of(JAVA_INT)
            );

            int configBufferSize = (int) configBufferSizeFunction.invoke();

            if (configBufferSize == -1) {
                throw new IllegalStateException("Failed to read IIS configuration size.");
            } 

            logger.debug("Reserving " + configBufferSize + " bytes for IIS configuration buffer.");

            // This function returns the content of the buffer. We know how much to allocate because we just called the size function.
            var configBufferFunction = Linker.nativeLinker().downcallHandle(
                lib.findOrThrow("get_binding_buffer"), 
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT)
            );

            MemorySegment configBuffer = arena.allocate(configBufferSize);
            MemorySegment errorBuffer = arena.allocate(1024); // Allocate a buffer for error messages

            int returnCode = (int) configBufferFunction.invoke(configBuffer, configBufferSize, errorBuffer, 1024);                
            
            if (returnCode != 0) {
                String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
                throw new IllegalStateException("IIS Configuration reading failed (code " + returnCode + "): " + errorDetails);
            }

            logger.info("Successfully read IIS configuration buffer.");

            var configJson = configBuffer.getString(0, StandardCharsets.UTF_8);
            logger.debug("IIS Configuration JSON: {}", configJson);


            String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
            if (!errorDetails.isEmpty()) {
                logger.warn("IIS Configuration reading returned warnings: {}", errorDetails);
            }

            return IisWebServerBridge.getSiteConfig(configJson);
        } catch (Throwable e) {
            logger.error("Error while reading IIS configuration", e);
            throw new RuntimeException("Failed to read IIS configuration", e);
        }

    }

    public static void applyConfig() {
        // Placeholder for applying IIS configuration logic
    }

}
