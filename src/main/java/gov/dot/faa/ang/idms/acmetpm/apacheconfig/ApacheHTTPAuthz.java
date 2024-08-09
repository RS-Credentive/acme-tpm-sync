package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

import org.slf4j.LoggerFactory;

import org.slf4j.Logger;

/**
 * ApacheHTTPAuthz is responsible for creating a file to support HTTP Authorization for an ACME Challenge
 */
public final class ApacheHTTPAuthz {
    static Logger logger = LoggerFactory.getLogger(ApacheHTTPAuthz.class);

    private static final Path challengePath = Path.of(".well-known", "acme-challenge");

    /**
     * Write a token file to the appropriate subdirectory with the expected name and contents.
     * @param docRoot - the Apache docroot to write to
     * @param token - the token value provided by the ACME server
     * @throws AcmeTpmException
     */
    public static void writeAuthzFile(Path docRoot, String token) throws AcmeTpmException {
        // TODO: We need to clean up these files after the certificate is downloaded
        Path authorizationResourceDirectory = docRoot.resolve(challengePath);
        Path authorizationResourceFile = authorizationResourceDirectory.resolve(token);
        logger.debug("Authorization Resource File: " + authorizationResourceFile);

        // check to see if directory exists. If not, create it.
        try {
            if (! authorizationResourceDirectory.toFile().exists()) {
                logger.debug("Directory " + authorizationResourceDirectory.toString() + " does not exist. Creating it...");
                authorizationResourceDirectory.toFile().mkdirs();
            }
        } catch (SecurityException e) {
            throw new AcmeTpmException("We don't have permission to create the directory " + authorizationResourceDirectory.toString());
        }

        if (! authorizationResourceFile.toFile().exists()) {
            try {
                authorizationResourceFile.toFile().createNewFile();
            } catch (IOException e) {
                throw new AcmeTpmException("Unable to create new file " + authorizationResourceFile.toString());
            }
        }

        try {
            Files.write(authorizationResourceFile, token.getBytes());
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to write token data to  " + authorizationResourceFile.toString());
        }

    }
}
