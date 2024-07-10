package gov.dot.faa.ang.idms.acmetpm.tpmcrypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpm;
import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

/* 
 * Class to encapsulate cryptographic functionality for a TPM-backed PKCS11 keystore for ACME
 * 
 * @author robert.sherwood@credentive.com
 * 
 */
public class TpmProvider {

    private static final Logger logger = LoggerFactory.getLogger(TpmProvider.class);
    private static final String TPM_PKCS11_CONFIG = AcmeTpm.TPM_JCA_CONFIG.toString();
    private static final String KEYPAIR_ALGORITHM = "EC";
    private static final String CERT_SIG_ALG = "SHA256withECDSA";
    private static final String EC_PARAM_SPEC = "secp256r1";
    private static final String USER_ALIAS = "userKeyPair";

    private static Provider tpmProvider; // Used for key generation, storage and private key operations
    private static Provider bcProvider; // Used for certificate generation and X.509 stuff
    private PasswordProtection tokenPassword;
    private KeyStore tpmKeyStore;
    private KeyPair userKeyPair;

    /**
     * This class encapsulates the behavior of the TPM backed PKCS11 token and
     * provides utility functions for key and certificate management.
     *
     * @param tokenPassword The user PIN or password to unlock the token.
     * @throws AcmeTpmException
     */
    public TpmProvider(String tokenPassword) throws AcmeTpmException {
        try {
            logger.debug("Intializing Token Provider");
            bcProvider = new BouncyCastleProvider();
            Security.addProvider(bcProvider);
            logger.debug("Loading SunPKCS11 configuration from {}", TPM_PKCS11_CONFIG);
            tpmProvider = Security.getProvider("SunPKCS11").configure("/" + TPM_PKCS11_CONFIG);
            Security.addProvider(tpmProvider);
            this.tpmKeyStore = KeyStore.getInstance("PKCS11-TpmAccelerator", tpmProvider);
            this.tokenPassword = new KeyStore.PasswordProtection(tokenPassword.toCharArray());
            logger.debug("Loading Keystore from TPM backed token.");
            this.tpmKeyStore.load(null, this.tokenPassword.getPassword());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            throw new AcmeTpmException(ex.getMessage());
        }
    }

    /**
     * getUserKeyPair returns the keypair for the user. It will load and/or
     * create the keypair if it does not exist, so it is guaranteed to return a
     * keypair or raise an Exception.
     *
     * @return The KeyPair associated with the user account on the ACME server.
     * @throws AcmeTpmException
     */
    public KeyPair getUserKeyPair() throws AcmeTpmException {
        if (this.userKeyPair != null) {
            logger.debug("userKeyPair already loaded, returning from Memory");
            return this.userKeyPair;
        } else {
            try {
                // Look for the KeyPair in the Token Keystore
                if (this.tpmKeyStore.containsAlias(USER_ALIAS)) {
                    logger.debug("Found userKeyPair in Keystore, retrieving");
                    PublicKey userPubKey = this.tpmKeyStore.getCertificate(USER_ALIAS).getPublicKey();

                    PrivateKey userPrivKey = ((PrivateKeyEntry) this.tpmKeyStore.getEntry(USER_ALIAS,
                            this.tokenPassword)).getPrivateKey();

                    this.userKeyPair = new KeyPair(userPubKey, userPrivKey);
                    logger.debug("Completed loading userKeyPair from keystore - returning.");
                    return this.userKeyPair;
                } else { // If it doesn't exist, create and return it.
                    logger.debug("userKeyPair not found in Keystore - creating Keystore");
                    this.userKeyPair = newKeyPair();
                    logger.debug("Calling storeKeyPair for userKeyPair");
                    storeKeyPair(USER_ALIAS, userKeyPair);
                    return this.userKeyPair;
                }
            } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException e) {
                throw new AcmeTpmException(e.getMessage());
            }
        }
    }

    /**
     * Returns a list of all domains managed in the TPM.
     * @return ArrayList<String>
     * @throws AcmeTpmException
     */
    public ArrayList<String> getDomains() throws AcmeTpmException {
        try {
            var domains = new ArrayList<String>();
            var domainEnum = this.tpmKeyStore.aliases();
            while (domainEnum.hasMoreElements()) {
                var nextDomain = domainEnum.nextElement();
                if (nextDomain.equals("userKeyPair")) {
                } else {
                    domains.add(nextDomain);
                }
            }
            return domains;
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Error enumerating key aliases: " + e.getMessage());
        }
    }

    /**
     * Returns true if the domain is managed in the TPM backed token, or false if it is not. We check for the domain in the list of keystor aliases.
     * @param String representing the domain name for the managed key
     * @return true if the keystore contains the alias, false if it does not.
     * @throws AcmeTpmException
     */
    public boolean isManagedDomain(String domain) throws AcmeTpmException {
        try {
            return this.tpmKeyStore.containsAlias(domain);
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Unable to check for managed domain " + domain + ". Error: " + e.getMessage());
        }
    }

    /**
     * Parses the certificate associated with a managed domain and returns the expiration date.
     * @param domain to check
     * @return Date object corresponding to the certificate's expiration date.
     * @throws AcmeTpmException
     */
    public Date domainCertExpiration(String domain) throws AcmeTpmException {
        if (isManagedDomain(domain)) {
            try {                
                X509Certificate domainCert = (X509Certificate)this.tpmKeyStore.getCertificate(domain);
                return domainCert.getNotAfter();
            } catch (KeyStoreException e) {
                throw new AcmeTpmException("Error attempting to determine expiration date for " + domain + ": " + e.getMessage());
            }
        } else {
            throw new AcmeTpmException(domain + " is not a managed domain.");
        }
    }

    /**
     * Returns the key pair corresponding to a hostname for this server. It will create the keypair if it doesn't exist.
     * Guaranteed to return a keypair or throw an error.
     * 
     * @param domain the dns name for the host
     * @return The keypair for that domain if it exists in the keystore
     * @throws AcmeTpmException if the attempt to retrieve or create the keypair fails
     */
    public KeyPair getDomainKeyPair(String domain) throws AcmeTpmException {
        logger.debug("Calling getDomainKeyPair for {}", domain);
        try {
            if (this.tpmKeyStore.containsAlias(domain)) {
                logger.debug("Found keypair for {} in Keystore, fetching", domain);
                PublicKey userPubKey = this.tpmKeyStore.getCertificate(domain).getPublicKey();
                PrivateKey userPrivKey = ((PrivateKeyEntry) this.tpmKeyStore.getEntry(domain, this.tokenPassword))
                        .getPrivateKey();
                logger.debug("Keypair successfully found, returning");
                return new KeyPair(userPubKey, userPrivKey);
            } else { // If it doesn't exist, create and return it.
                logger.debug("No keypair in keystore for {}, creating it.", domain);
                KeyPair domainKeyPair = newKeyPair();
                logger.debug("KeyPair successfully created, storing in token...");
                storeKeyPair(domain, domainKeyPair);
                logger.debug("Keypair successfully stored, returning.");
                return domainKeyPair;
            }
        } catch (Exception e) {
            throw new AcmeTpmException(e.getMessage());
        }
    }

    /**
     * Returns the pkcs11 paths for a private key and certificate pair stored in the TPM backed token
     * @param The domain name corresponding the the keypair alias
     * @return a Hashmap containing the private and public pkcs11 paths for the private and public keys.
     */
    public HashMap<String, String> getPathsForTpmObjects(String domain) throws AcmeTpmException {
        // Initialize the PKCS11 utility
        var pkcs11Util = new UtilPKCS11(domain);

        // Get the pkcs11 paths
        return pkcs11Util.getPaths();
    }

    /**
     * Returns an SSLContext for the TpmProvider. Used for client authenticated SSL connections to the ACME server
     * 
     * @return an SSL context which will leverage the TPM backed keys.
     * @throws AcmeTpmException if the SSL Context cannot be created
     */
    public SSLContext getSSLContext() throws AcmeTpmException {
        logger.info("Loading Client Keystore using PKCS11, with config {}", TPM_PKCS11_CONFIG);
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(this.tpmKeyStore, AcmeTpm.CLIENT_KEY_STORE_PIN.toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            logger.info("Loaded {} key managers", keyManagers.length);

            KeyStore trustStore = getTrustStore();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            TrustManager[] trustManagers = tmf.getTrustManagers();

            sslContext.init(keyManagers, trustManagers, new java.security.SecureRandom());
            return sslContext;
        } catch (AcmeTpmException | KeyManagementException | KeyStoreException
                | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new AcmeTpmException(e.getMessage());
        }
    }

    /**
     * private class to create a keypair in the virtual token
     * @return a KeyPair
     * @throws AcmeTpmException
     */
    private KeyPair newKeyPair() throws AcmeTpmException {
        KeyPairGenerator kpGen;
        try {
            logger.debug("Attempting to create new " + KEYPAIR_ALGORITHM + " keys with parameters" + EC_PARAM_SPEC);
            kpGen = KeyPairGenerator.getInstance(KEYPAIR_ALGORITHM, tpmProvider);
            kpGen.initialize(new ECGenParameterSpec(EC_PARAM_SPEC), new SecureRandom());
            logger.debug("Keypair successfully created, returning");
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw new AcmeTpmException(ex.getMessage());
        }

    }

    /**
     * Stores a keypair in the TPM backed token. Generates a self-signed certificate which shouldn't be used for real.
     * @param alias the desired alias for the keypair this should be either the USER_ALIAS, or the domain name identifying the web server or certificates.
     * @param keyPair the keypair to store
     * @throws AcmeTpmException if the storage of the keypair fails.
     */
    private void storeKeyPair(String alias, KeyPair keyPair) throws AcmeTpmException {
        try {
            if (this.tpmKeyStore.containsAlias(alias)) {
                logger.error("Called storeKeyPair for {} which already exists in the keyStore. This should not happen", alias);
                throw new AcmeTpmException("KeyPair with alias " + alias + " already exists");
            } else {
                logger.debug("Generating self-signed certificate for {}", alias);
                X500Name distinguishedName = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Self").build();
                X509CertificateHolder certHolder = new X509v3CertificateBuilder(
                        distinguishedName, // Issuer NAme
                        new BigInteger("1"), // Serial Number
                        Date.from(Instant.now()), // notBefore - now
                        Date.from(Instant.now().plus(Duration.ofDays(365))), // notAfter - 1 year
                        distinguishedName, // Subject Name
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()) // Public Key
                ).build(new JcaContentSignerBuilder(CERT_SIG_ALG).build(keyPair.getPrivate()));

                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
                logger.debug("Certificate created, storing under alias {}", alias);
                this.tpmKeyStore.setKeyEntry(alias, keyPair.getPrivate(), this.tokenPassword.getPassword(), new X509Certificate[]{cert});
            }
        } catch (KeyStoreException | AcmeTpmException | CertificateException | OperatorCreationException e) {
            throw new AcmeTpmException(e.getMessage());
        }
    }

    /**
     * This function is called when an updated certificate is obtained from the ACME server. It update the keypair in the token
     * @param alias the alias of the keypair to update
     * @param certHolder a certificateHolder object to be converted into a certificate and stored in the token.
     */
    private void updateCertificate(String alias, X509CertificateHolder certHolder) {
        // Accept a certificate and update the pkcs11 store with the cert in the right
        // alias

    }

    /**
     * gets the Trust store containing the Issuing CA Certificates. Used by getSSLContext.
     * @return the Keystore representing the trust store containing the CA public key certificates
     * @throws AcmeTpmException if the keystore does not exist or cannot be loaded.
     */
    private KeyStore getTrustStore() throws AcmeTpmException {
        KeyStore keystore;
        try {
            String trustStorePassword = AcmeTpm.CLIENT_KEY_STORE_PIN;
            keystore = KeyStore.getInstance("PKCS12");

            final File keystoreFile = AcmeTpm.EJBCA_TRUSTSTORE.toFile();

            logger.info("Loading keystore from file {}", keystoreFile);
            InputStream keystoreStream = new FileInputStream(keystoreFile);

            keystore.load(keystoreStream, trustStorePassword.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new AcmeTpmException(e.getMessage());
        }
        return keystore;
    }

    public HashMap<String, String> getKeyInfo(String domainString) throws AcmeTpmException {
        try {
            var keyInfoHashMap = new HashMap<String, String>();
            if (this.tpmKeyStore.containsAlias(domainString)) {
                this.tpmKeyStore.getCreationDate(domainString);
                keyInfoHashMap.put("keySize", domainString);
                return keyInfoHashMap;
            } else {
                throw new AcmeTpmException(domainString + "  is not a managed domain.");
            }
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Unable to access key for " + domainString + ": " + e.getMessage());
        }
    }



}
