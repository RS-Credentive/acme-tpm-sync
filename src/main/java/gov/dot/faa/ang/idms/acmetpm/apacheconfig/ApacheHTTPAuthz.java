package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

/**
 * ApacheHTTPAuthz is responsible for creating a file to support HTTP Authorization for an ACME Challenge
 */
public final class ApacheHTTPAuthz {
    private static final Path challengePath = Path.of(".well-known", "acme-challenge");

    /**
     * Write a token file to the appropriate subdirectory with the expected name and contents.
     * @param docRoot - the Apache docroot to write to
     * @param token - the token value provided by the ACME server
     * @throws AcmeTpmException
     */
    public static void writeAuthzFile(Path docRoot, String token) throws AcmeTpmException {
        Path authorizationResourcePath = docRoot.resolve(challengePath).resolve(token);
        try {
            Files.write(authorizationResourcePath, token.getBytes());
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to create authorization Resource File at " + authorizationResourcePath.toString());
        }
    }

}
