package gov.dot.faa.ang.idms.acmetpm;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyPair;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.provider.AcmeProvider;

import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;
import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

/**
 * Wraps calls to the EJBCA ACME API, leveraging TPM Backed private keys and updating the apache configuration
 *
 * @author robert.sherwood@credentive.com
 */
public class AcmeTpm {
    public static final Path BASEPATH = FileSystems.getDefault().getPath("home", "robert.ctr.sherwood", "Projects",
            "acmetpm");
    public static final Path TPM_JCA_CONFIG = BASEPATH.resolve("acmetpm.conf");
    public static final Path EJBCA_TRUSTSTORE = BASEPATH.resolve("idmsTrustStore.p12");
    public static final Path PROPS_FILE = BASEPATH.resolve("acmetpm.properties");

    public static final String CLIENT_KEY_STORE_PIN = "userpin";

    private static final String CA_URI = "acme://example.com/staging";

    public static String[] EJBCA_SERVERS;
    public static PropLoader props;
    public static String tokenPassword;
    public TpmProvider tpmProvider;


    public AcmeTpm(String server, String domain) {
        // Verify the properties file
        try {
            props = new PropLoader(PROPS_FILE);
            tokenPassword = props.getTokenPassword();
        } catch (AcmeTpmException ex) {
            System.out.println(ex);
            System.exit(1);
        }        

        // Load the TPM Keystore
        try {
            tpmProvider = new TpmProvider(CLIENT_KEY_STORE_PIN);
        } catch (Exception e) {
            System.out.println(e);
            System.exit(1);
        }

        KeyPair domainKeys;
        // Get or create key for requested domain
        try {
            domainKeys = tpmProvider.getDomainKeyPair(domain);
        } catch (AcmeTpmException e) {
            System.out.println(e.getLocalizedMessage());
            System.exit(1);
        }

        // Create a Session with the EJBCA Server
        URI caUri=null; 
        try {
            caUri = new URI(CA_URI);
        } catch (URISyntaxException e) {
            System.out.println(e);
            System.exit(1);
        }

        Session session;
        AcmeProvider idmsProvider = new IdmsAcmeProvider();
        if (caUri != null) {
            session = new Session(caUri, idmsProvider);
        }
        // Look for a KeyPair associated with the domain, if none exists, create one.

        // call the custom proxy to confirm everything is in place

        // Create the challenge (DNS first)

        // Generate CSR

        // Order Certificate from ACME server

        // Poll status, retrieve certificate

        // Install certificate in token

        // Install Certificate in Server
    }
}
