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

import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Metadata;
import org.shredzone.acme4j.Order;

import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;
import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;

/**
 * Wraps calls to the EJBCA ACME API, leveraging TPM Backed private keys and updating the apache configuration
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


    public AcmeTpm() throws AcmeTpmException {
        System.out.println("BASEPATH: " + BASEPATH.toString());
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

        // Parse the EJBCA URI 
        try {
            caUri = new URI(props.getProp("ejbca.sessionUri"));
        } catch (URISyntaxException e) {
            throw new AcmeTpmException("Invalid URI provided: " + props.getProp("ejbca.sessionUri"));
        }

        // Get our customized provider
        AcmeProvider idmsProvider = new IdmsAcmeProvider(getSSLContext());

        // Create the session
        acmeSession = new Session(caUri, idmsProvider);
    }

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

    private Account getUserAccount() throws AcmeTpmException {
        // TODO: Not sure this is quite correct - especially the round trip to login and retrieve
        // the account from the URL. Expensive!
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

    // private Account requestAcmeAccount(String email) throws AcmeTpmException {
    //     AccountBuilder accountBuilder = new AccountBuilder()
    //                 .agreeToTermsOfService()
    //                 .withKeyIdentifier(tokenPassword, tokenPassword);
        
    //     accountBuilder.addEmail(email);
    //     try {
    //         Account account = accountBuilder.create(acmeSession);
    //     } catch (AcmeException e) {
    //         throw new AcmeTpmException("Unable to create account: " + e.getMessage());
    //     }
    // }

    public void requestDomainCertificate(String csr) throws AcmeTpmException {
        
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
        return tpmProvider.getCsrPem(props.getProp("token.userAlias"));
    }

    public void updateUserCert(String certPEM) throws AcmeTpmException {
        tpmProvider.updateCertificate(props.getProp("token.userAlias"), certPEM);
    }

    public String generateCSR(String domain) throws AcmeTpmException {
        var domainCertRequest = tpmProvider.getCsrPem(domain);
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
            Account account = getUserAccount();
            Order domainOrder = account.newOrder().domain(domain).create();
            for (var authorization: domainOrder.getAuthorizations()) {
                // Perform Authorization
            }
            domainOrder.execute(tpmProvider.getCertRequestDER(domain));
            Status status = 
        } catch (AcmeTpmException | AcmeException e) {
            throw new AcmeTpmException("Unable to order certificate for " + domain + ": " + e.getMessage());
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
