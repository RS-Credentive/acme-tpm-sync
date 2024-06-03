package gov.dot.faa.ang.idms.acmetpm;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyStore;


/**
 * Wraps calls to the EJBCA Rest API.
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

    public static String[] EJBCA_SERVERS;
    public static PropLoader props;
    public static String tokenPassword;

    public AcmeTpm(String server, String domain) {
        // Verify the properties file
        try {
        props = new PropLoader(PROPS_FILE);
        } catch (AcmeTpmException ex) {
            System.out.println(ex);
            System.exit(1);
        }        

        // Load the TPM Keystore
        try {
            tokenPassword = props.getTokenPassword();
        } catch (AcmeTpmException e) {
            System.out.println(e);
            System.exit(1);
        }

        // Get the user Key
        try {
            
        } catch (Exception e) {
            // TODO: handle exception
        }






        

        // Create a Session with the EJBCA Server


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
