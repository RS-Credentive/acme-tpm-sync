package gov.dot.faa.ang.idms.acmetpm;

import java.io.File;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Metadata;
import org.shredzone.acme4j.Order;

import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;
import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;
import gov.dot.faa.ang.idms.acmetpm.apacheconfig.ApacheConfigReader;
import gov.dot.faa.ang.idms.acmetpm.apacheconfig.ApacheHTTPAuthz;

/**
 * Wraps calls to the EJBCA ACME API, leveraging TPM Backed private keys and updating the 
 * apache configuration
 *
 * @author robert.sherwood@credentive.com
 */
public class AcmeTpm {
    private static final Path ROOT_PATH = FileSystems.getDefault().getPath("").toAbsolutePath().getRoot();
    private static final Path BASEPATH = ROOT_PATH.resolve(Path.of("home", "robert.ctr.sherwood", "Projects",
            "acmetpm"));
    private static final Path TPM_JCA_CONFIG = BASEPATH.resolve("acmetpm.conf");
    private static final Path EJBCA_TRUSTSTORE = BASEPATH.resolve("idmsTrustStore.p12");

    public static String[] EJBCA_SERVERS;
    private static PropLoader props;
    private static String tokenPassword;
    private TpmProvider tpmProvider;
    private URI caUri;
    private Session acmeSession;
    private Account account;
    private List<Order> pendingOrders;
    private ApacheConfigReader apacheConfig;

    public AcmeTpm() throws AcmeTpmException {
        // Verify the properties file
        props = new PropLoader();
        tokenPassword = props.getTokenPassword();


        // Load the TPM Keystore
        tpmProvider = new TpmProvider(tokenPassword, TPM_JCA_CONFIG.toString());


        // Parse the EJBCA URI 
        try {
            caUri = new URI(props.getProp("ejbca.sessionUri"));
        } catch (URISyntaxException e) {
            throw new AcmeTpmException("Invalid URI provided for CA: " + props.getProp("ejbca.sessionUri"));
        }

        // Get our customized provider
        AcmeProvider idmsProvider = new IdmsAcmeProvider(getSSLContext());
        

        // Create the session
        acmeSession = new Session(caUri, idmsProvider);

        // Get the account
        account = getUserAccount();

        // Read the apache configuration
        apacheConfig = new ApacheConfigReader();
    }

    public HashMap<String, HashMap<String, String>> listApacheVirtualHosts() throws AcmeTpmException {
        HashMap<String, HashMap<String, String>> apacheVhosts = new HashMap<>();
        for (String vhost: apacheConfig.getVHosts()) {
            HashMap<String,String> vhostConfig = new HashMap<>();
            vhostConfig.put("Document Root", apacheConfig.getDocumentRootforVHost(vhost));
            vhostConfig.put("Private Key Location", apacheConfig.getKeyLocationForVHost(vhost));
            vhostConfig.put("Certificate Location", apacheConfig.getCertLocationforVHost(vhost));
            apacheVhosts.put(vhost, vhostConfig);
        }
        return apacheVhosts;
    }

    /**
     * Function to test connectivity to the ACME server by hitting the metadata endpoint
     * @return A HashMap of the metadata key/values
     * @throws AcmeTpmException
     */
    public HashMap<String, String> testAcmeConnection() throws AcmeTpmException {
        HashMap<String, String> metadataProps = new HashMap<>();
        try {
            Metadata acmeMeta = acmeSession.getMetadata();
            JSON metadataJson = acmeMeta.getJSON();
            for (String key: metadataJson.keySet()) {
                metadataProps.put(key, metadataJson.get(key).asString());
            }
            return metadataProps;
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to connect to Acme Server: " + e.getMessage());
        }
    }

    /**
     * Gets or creates the user account 
     * @return
     * @throws AcmeTpmException
     */
    private Account getUserAccount() throws AcmeTpmException {
        // TODO: Not sure this is quite correct - especially the round trip to login 
        // and retrieve the account from the URL. Expensive!
        String accountURLProp = props.getProp("acme.accountURL");
        Account userAccount;

        if (accountURLProp == null) {
            String userEmail = props.getProp("acme.userEmail");
            userAccount = requestAcmeAccount(userEmail);
            props.setProp("acme.accountURL", userAccount.getLocation().toString());
        } else {
            try {
                URL accountURL = new URL(accountURLProp);
                Login login = acmeSession.login(accountURL, tpmProvider.getUserKeyPair());
                return login.getAccount();
            } catch (MalformedURLException e) {
                throw new AcmeTpmException(accountURLProp);
            }
        }
        
        return userAccount;


    }

    private Account requestAcmeAccount(String email) throws AcmeTpmException {
        AccountBuilder accountBuilder = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(tpmProvider.getUserKeyPair());
        
        accountBuilder.addEmail(email);
        try {
            Account account = accountBuilder.create(acmeSession);
            return account;
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to create account: " + e.getMessage());
        }
    }

    public void requestDomainCertificate(byte[] csrDER) throws AcmeTpmException {
        
        // TODO: call the custom proxy to confirm everything is in place

        // TODO: Create the challenge (DNS first)

        // Order Certificate 

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
        return tpmProvider.getCertRequestPEM(props.getProp("token.userAlias"));
    }

    /**
     * Updates the certificate associated with the Acme User account
     * @param certPEM
     * @throws AcmeTpmException
     */
    public void updateUserCert(String certPEM) throws AcmeTpmException {
        tpmProvider.updateCertificate(props.getProp("token.userAlias"), certPEM);
    }

    /**
     * Generates a CSR for a domain. Returns byte[] for use by the acme server.
     * @param domain
     * @return
     * @throws AcmeTpmException
     */
    public byte[] generateDomainCSR(String domain) throws AcmeTpmException {
        var domainCertRequest = tpmProvider.getCertRequestDER(domain);
        return domainCertRequest;
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

    /**
     * Checks for a keypair associated with an alias
     * @param alias to check for in the TPM keystore
     * @return true if alias exists, false otherwise
     * @throws AcmeTpmException
     */
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
        try {
            tpmProvider.addKeyPair(domain);
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Unable to order certificate for " + domain + ": " + e.getMessage());
        }
    }

    /**
     * Submits a certificate request for a domain to an ACME server
     * @param domain the domain to submit the request for
     * @param request the CSR as a DER encoded byte[]
     * @throws AcmeTpmException
     */
    public void submitRequest(String domain, byte[] request) throws AcmeTpmException {
        Order domainOrder;

        try {
            domainOrder = account.newOrder().domain(domain).create();
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to initialize order for " + domain + ": " + e.getMessage());
        }

        processOrder(domainOrder);

    }

    private void processOrder(Order order) throws AcmeTpmException {
        switch (order.getStatus()) {
            case PENDING:
                // check and fulfill authorizations
                processAuthorizations(order.getAuthorizations());
                break;
            case READY:
                // finalize order
                break;
            case PROCESSING:
                // wait - careful about recursive calls!
                break;
            case VALID:
                // fetch certificate
                break;
            case INVALID:
                // order failed - cancel
                break;
            default:
                throw new AcmeTpmException("Unrecognized order status: " + order.getStatus().toString());
        }
    }

    private void processAuthorizations(List<Authorization> authorizations) throws AcmeTpmException {
        for (var authorization: authorizations) {
            switch (authorization.getStatus()) {
                case PENDING:
                    String domain = authorization.getIdentifier().getDomain();
                    processChallenges(domain, authorization.getChallenges());
                    break;
                case EXPIRED:
                    // retry order?
                    break;
                case DEACTIVATED:
                    // retry order?
                    break;
                case REVOKED:
                    // retry order?
                    break;
                case INVALID:
                    // retry order?
                    break;
                case VALID:
                    // wait and then end, so that the calling function can retry
                    break;
                default:
                throw new AcmeTpmException("Unrecognized authorization status: " + authorization.getStatus().toString());
            }
        }
    }

    private void processChallenges(String domain, List<Challenge> challenges) throws AcmeTpmException {
        for (var challenge: challenges) {
            switch (challenge.getStatus()) {
                case PENDING:
                    processChallenge(domain, challenge);
                    break;
                case PROCESSING:
                    // wait
                    break;
                case INVALID:
                    // throw error 
                    break;
                case VALID:
                    // return to caller, so that the caller can fetch the certificate
                    break;
                default:
                    throw new AcmeTpmException("Unrecognized challenge status: " + challenge.getStatus().toString());
            }
        }

    }

    private void processChallenge(String domain, Challenge challenge) throws AcmeTpmException {
        switch (challenge.getType()) {
            case "http-01":
                processHttpChallenge(domain, (Http01Challenge) challenge);
                break;
            // Can't process DNS challenges until proxy is completed.
            // case "dns-01":
            //     processDnsChallenge(domain, (Dns01Challenge) challenge);
            //     break;
            default:
                throw new AcmeTpmException("Challenge type " + challenge.getType() + " unrecognized or unimplemented.");
        }

    }

    /**
     * Process a pending HTTP challenge
     * @param challenge
     * @throws AcmeTpmException
     */
    private void processHttpChallenge(String domain, Http01Challenge challenge) throws AcmeTpmException {
        // If we got here, the status is pending and the type is HTTP, so we just need to create the expected file.
        String token = challenge.getToken();
        
        Path authorizationResourcePath = Path.of(apacheConfig.getDocumentRootforVHost(domain));
        ApacheHTTPAuthz.writeAuthzFile(authorizationResourcePath, token);
        
    }


    /**
     * Process a DNS challenge, and add or update the dnsChallenge list
     * @param domain
     * @param dnsChallenge
     * @throws AcmeTpmException
     */
    private void processDnsChallenge(Dns01Challenge dnsChallenge) throws AcmeTpmException {
        switch (dnsChallenge.getStatus()) {
            case PENDING: // Server has not completed the authorization.
            case PROCESSING: // Validation completed, system processing
            case VALID: // Authorizations are successful. Finalize the order.                
                // challenges.put(
                //     domain, 
                //     new DnsChallengeTracker(
                //         Dns01Challenge.toRRName(domain), 
                //         dnsChallenge.getDigest(), 
                //         dnsChallenge.getStatus().toString()
                //     )
                // );
                break;
            case INVALID: // Authorizations Expired. Throw an error
                throw new AcmeTpmException("Challenge processed, but invalid.");
            default:
                throw new AcmeTpmException(
                    "Unrecognized challenge status: " + dnsChallenge.getStatus().toString()
                );
        }
    }

    public void fetchAndInstallCertificate(String domain) {
        // Dns01Challenge
        // try {
            
        // } catch (Exception e) {
        //     // TODO: handle exception
        // }
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
