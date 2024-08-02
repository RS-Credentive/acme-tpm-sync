package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

/**
 * ApacheHTTPAuthz is responsible for creating a file to support HTTP Authorization for an ACME Challenge
 */
public class ApacheHTTPAuthz {
    private static final Path challengePath = Path.of(".well-known", "acme-challenge");

    /**
     * Constructor
     * @param reader an ApacheConfigReader
     */
    public ApacheHTTPAuthz() {

    }

    public static void writeAuthzFile(Path docRoot, String token) throws AcmeTpmException {
        Path authorizationResourcePath = docRoot.resolve(challengePath).resolve(token);
        try {
            Files.write(authorizationResourcePath, token.getBytes());
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to create authorization Resource File at " + authorizationResourcePath.toString());
        }
    }

}
