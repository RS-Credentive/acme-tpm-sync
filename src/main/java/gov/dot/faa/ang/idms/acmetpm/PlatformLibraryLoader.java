package gov.dot.faa.ang.idms.acmetpm;

import module java.base;

import gov.dot.faa.ang.idms.acmetpm.crypto.bridge.CapiTpmBridge;

public class PlatformLibraryLoader {
    private static final String DLL_PATH = "/native/windows-x86_64/WindowsHelperFunctions.dll";

    public static Path loadPlatformLibrary() throws IOException {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return createTmpDllPath();
        } else {
            throw new UnsupportedOperationException("No loadable library for this platform.");
        }        
        
    }

    
    private static Path createTmpDllPath() throws IOException {
        try (var dllin = CapiTpmBridge.class.getResourceAsStream(DLL_PATH)) {
            if (dllin == null) {
                throw new IllegalStateException("Bundled Platform dll not found.");
            }

            var tempDll = Files.createTempFile("WindowsHelperFunctions", ".dll").toFile();  // This is *literally* Sonarqube's suggested fix, which it is tagging as non-compliant

            // Set the file permissions to be readable and writable only by the owner. Bail if it doesn't work.
            // This is a security measure to prevent other users from accessing the temporary DLL.
            if (!tempDll.setReadable(true, true) || 
                !tempDll.setWritable(true, true)) {
                    throw new IOException("Unable to set file permissions safely for temporary file");
            }

            tempDll.deleteOnExit();

            var tempDllPath = tempDll.toPath();
            Files.copy(dllin, tempDllPath, StandardCopyOption.REPLACE_EXISTING);
            return tempDllPath;   
        }
    }

}
