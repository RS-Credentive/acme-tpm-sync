package gov.dot.faa.ang.idms.acmetpm;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import javax.net.ssl.SSLContext;

import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

/**
 * Wraps calls to the EJBCA ACME API, leveraging TPM Backed private keys and updating the apache configuration
 *
 * @author robert.sherwood@credentive.com
 */
public class AcmeTpm {
    private static final Path BASEPATH = FileSystems.getDefault().getPath("home", "robert.ctr.sherwood", "Projects",
            "acmetpm");
    private static final Path TPM_JCA_CONFIG = BASEPATH.resolve("acmetpm.conf");
    private static final Path EJBCA_TRUSTSTORE = BASEPATH.resolve("idmsTrustStore.p12");

    public static String[] EJBCA_SERVERS;
    private static PropLoader props;
    private static String tokenPassword;
    private TpmProvider tpmProvider;


    public AcmeTpm() throws AcmeTpmException {
        // Verify the properties file
        try {
            props = new PropLoader();
            tokenPassword = props.getTokenPassword();
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException(e.getMessage());
        }        

        // Load the TPM Keystore
        try {
            tpmProvider = new TpmProvider(tokenPassword, TPM_JCA_CONFIG.toString());
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException(e.getMessage());
        }

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

        /**
     * Returns information related to keys 
     * @param domainString
     * @return
     * @throws AcmeTpmException
     */
    public HashMap<String, String> getUserKeyInfo() throws AcmeTpmException {
        return tpmProvider.getKeyInfo(props.getProp("token.userAlias"));
    }

    /**
     * Returns information related to keys 
     * @param domainString
     * @return
     * @throws AcmeTpmException
     */
    public HashMap<String, String> getKeyInfo(String domainString) throws AcmeTpmException {
        return tpmProvider.getKeyInfo(domainString);
    }

    /**
     * Generates a CSR for the userKeyPair and returns it as a PEM encoded string.
     * @param keyPairAlias - the alias of the keypair for which to generate the CSR
     * @return PEM encoded String representing the CSR.
     * @throws AcmeTpmException
     */
    public String generateUserCSR() throws AcmeTpmException {
        return tpmProvider.getCSR(props.getProp("token.userAlias"));
    }

    public void updateUserCert(String certPEM) throws AcmeTpmException {
        tpmProvider.updateCertificate(props.getProp("token.userAlias"), certPEM);
    }

    /**
     * Prints information about the keypairs and certificats for one of the domains under management
     * @param domainString - a string representing a domain, usually a hostname
     * @return keys and information related to the keys
     */
    public HashMap<String, String> getDomainInfo(String domainString) throws AcmeTpmException {
        try {
            if (tpmProvider.hasAlias(domainString)) {
                return tpmProvider.getKeyInfo(domainString);
            } else {
                // return an empty hashmap
                return new HashMap<String, String>();
            }
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error while attempting to get info for domain " + domainString + ": " + e.getMessage());
        }
    }

    public boolean hasKeyPair(String alias) throws AcmeTpmException {
        return tpmProvider.hasAlias(alias);
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
     * Adds a new domain to the managed domain list, generating and storing a key pair.
     * Note that if the domain already exists, nothing changes and the keys are not modified.
     * 
     * @param domain
     * @throws AcmeTpmException
     */
    public void addDomain(String domain) throws AcmeTpmException {
        tpmProvider.addKeyPair(domain);
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

    /**
     * Returns an SSLContext from the tpmProvider. Used for client authenticated SSL connections to the ACME server
     * 
     * @return an SSL context which will leverage the TPM backed keys.
     * @throws AcmeTpmException if the SSL Context cannot be created
     */
    public SSLContext getSSLContext() throws AcmeTpmException {
        return tpmProvider.getSSLContext(EJBCA_TRUSTSTORE);
    }
}
