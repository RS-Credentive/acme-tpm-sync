package gov.dot.faa.ang.idms.acmetpm;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

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

    public static String[] EJBCA_SERVERS;
    public static PropLoader props;
    public static String tokenPassword;
    public TpmProvider tpmProvider;


    public AcmeTpm() {
        // Verify the properties file
        try {
            props = new PropLoader();
            tokenPassword = props.getTokenPassword();
        } catch (AcmeTpmException ex) {
            System.out.println(ex);
            System.exit(1);
        }        

        // Load the TPM Keystore
        try {
            tpmProvider = new TpmProvider(tokenPassword);
        } catch (Exception e) {
            System.out.println(e);
            System.exit(1);
        }

        // KeyPair domainKeys;
        // // Get or create key for requested domain
        // try {
        //     domainKeys = tpmProvider.getDomainKeyPair(domain);
        // } catch (AcmeTpmException e) {
        //     System.out.println(e.getLocalizedMessage());
        //     System.exit(1);
        // }

        // Create a Session with the EJBCA Server
        // URI caUri=null; 
        // try {
        //     caUri = new URI(CA_URI);
        // } catch (URISyntaxException e) {
        //     System.out.println(e);
        //     System.exit(1);
        // }

        // Session session;
        // AcmeProvider idmsProvider = new IdmsAcmeProvider();
        // if (caUri != null) {
        //     session = new Session(caUri, idmsProvider);
        // }
        // Look for a KeyPair associated with the domain, if none exists, create one.

        // call the custom proxy to confirm everything is in place

        // Create the challenge (DNS first)

        // Generate CSR

        // Order Certificate from ACME server

        // Poll status, retrieve certificate

        // Install certificate in token

        // Install Certificate in Server
    }

    public String generateCSR(String keyPairAlias) {
        if (tpmProvider.)
    }

    /**
     * Prints information about the keypairs and certificats for one of the domains under management
     * @param domainString - a string representing a domain, usually a hostname
     * @return keys and information related to the keys
     */
    public HashMap<String, String> getDomainInfo(String domainString) throws AcmeTpmException {
        try {
            if (tpmProvider.isManagedDomain(domainString)) {
                return tpmProvider.getKeyInfo(domainString);
            } else {
                // return an empty hashmap
                return new HashMap<String, String>();
            }
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error while attempting to get info for domain " + domainString + ": " + e.getMessage());
        }
    }

    /**
     * returns a list of managed domains, which may be an empty list.
     * @return a list
     */
    public ArrayList<String> listDomains() throws AcmeTpmException {
        try {
            return tpmProvider.getDomains();
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error receieved while trying to list Domains: " + e.getMessage());
        }
    }

    /**
     * print a list of domains that will expire before the date provided
     * @param expirationDate - the expiration date to compare the domain certificates against. If not provided, it will be looked up in the property file.
     * @return a list of domains that will expire before the date provided, which may be empty
     */
    public HashMap<String, Date> getExpiringDomains(Date expirationDate) throws AcmeTpmException {
        // if expiration date is not set, set it to the default configured in properties
        try {
            if (expirationDate == null) {
                int renewalLimit = Integer.valueOf(props.getProp("domains.renewalLimit"));
                expirationDate = Date.from(Instant.now().plus(Duration.ofDays(renewalLimit)));
            }
        } catch (NumberFormatException e) {
            throw new AcmeTpmException("Error setting the renewal limit from properties: " + e.getMessage());
        }

        // Populate hashmap with "domain" : certificate expiration date if it is after the passed in date
        var expiringDomainHashMap = new HashMap<String, Date>();
        try {
            var domains = listDomains();
            if (domains.size() > 0) {
                for (var domain : domains) {
                    if (tpmProvider.domainCertExpiration(domain).after(expirationDate))
                        expiringDomainHashMap.put(domain, expirationDate);
                }
            }
            return expiringDomainHashMap;
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error getting expiration dates from TPM backed token: " + e.getMessage());
        }

    }
}
