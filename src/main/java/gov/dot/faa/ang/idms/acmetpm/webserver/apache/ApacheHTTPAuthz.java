package gov.dot.faa.ang.idms.acmetpm.webserver.apache;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

/**
 * ApacheHTTPAuthz is responsible for creating a file to support HTTP Authorization for an ACME Challenge
 */
public final class ApacheHTTPAuthz {
    static Logger logger = LoggerFactory.getLogger(ApacheHTTPAuthz.class);

    private static final Path challengePath = Path.of(".well-known", "acme-challenge");

    static final Set<PosixFilePermission> RW_R_R_PERMISSION = PosixFilePermissions.fromString("rw-r--r--");

    /**
     * Write a token file to the appropriate subdirectory with the expected name and contents.
     * @param docRoot - the Apache docroot to write to
     * @param token - the token value provided by the ACME server
     * @throws AcmeTpmException
     */
    public static void createAuthzFile(Path docRoot, String token, String authorization) throws AcmeTpmException {
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
                Files.setPosixFilePermissions(authorizationResourceFile, RW_R_R_PERMISSION);
            } catch (IOException e) {
                throw new AcmeTpmException("Unable to create new file " + authorizationResourceFile.toString());
            }
        }

        try {
            Files.write(authorizationResourceFile, authorization.getBytes());
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to write token data to  " + authorizationResourceFile.toString());
        }

    }

    public static void deleteAuthzFile(Path docRoot, String token) throws AcmeTpmException {
        Path authorizationResourceDirectory = docRoot.resolve(challengePath);
        Path authorizationResourceFile = authorizationResourceDirectory.resolve(token);

        try {
            Files.delete(authorizationResourceFile);
        } catch (IOException e) {
            logger.info("Error when attempting to delete authorization resource file, {}. Ignoring.", authorizationResourceFile.toString());
        }
    }
}
