package gov.dot.faa.ang.idms.acmetpm.tpmcrypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Path;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

/* 
 * Class to encapsulate cryptographic functionality for a TPM-backed PKCS11 keystore for ACME
 * 
 * @author robert.sherwood@credentive.com
 * 
 */
public class TpmProvider {

    private static final Logger logger = LoggerFactory.getLogger(TpmProvider.class);
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
    public TpmProvider(String tokenPassword, String jcaConfigFilePath) throws AcmeTpmException {
        try {
            logger.debug("Intializing Token Provider");
            bcProvider = new BouncyCastleProvider();
            Security.addProvider(bcProvider);
            logger.debug("Loading SunPKCS11 configuration from {}", jcaConfigFilePath);
            tpmProvider = Security.getProvider("SunPKCS11").configure("/" + jcaConfigFilePath);
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
            KeyPair keypair = null;
            try {
                // Look for the KeyPair in the Token Keystore
                keypair = getKeyPair(USER_ALIAS);
                logger.debug("Completed loading userKeyPair from keystore - returning.");
                if (keypair == null) {
                    logger.debug("User keypair did not exist, creating it.");
                    keypair = newKeyPair();
                    storeKeyPair(USER_ALIAS, keypair);
                }
                this.userKeyPair = keypair;
                return keypair;
            } catch (AcmeTpmException e) {
                throw new AcmeTpmException("Unable to get userKeyPair: " + e.getMessage());
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
    public boolean hasAlias(String domain) throws AcmeTpmException {
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
        if (hasAlias(domain)) {
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
     * Generates and stores a key pair for an alias. It will create the keypair if it doesn't exist.
     * 
     * @param alias the dns name for the host
     * @return The keypair for that alias if it exists in the keystore
     * @throws AcmeTpmException if the attempt to retrieve or create the keypair fails
     */
    public void addKeyPair(String alias) throws AcmeTpmException {
        logger.debug("Calling getaliasKeyPair for {}", alias);
        try {
            if (this.tpmKeyStore.containsAlias(alias)) {
                logger.debug("Found keypair for {} in Keystore, fetching", alias);
                logger.debug("Keypair successfully found, returning");
            } else { // If it doesn't exist, create and return it.
                logger.debug("No keypair in keystore for {}, creating it.", alias);
                KeyPair keyPair = newKeyPair();
                logger.debug("KeyPair successfully created, storing in token...");
                storeKeyPair(alias, keyPair);
                logger.debug("Keypair successfully stored, returning.");
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
    public SSLContext getSSLContext(Path trustStorePath) throws AcmeTpmException {
        logger.info("Loading Client Keystore using PKCS11");
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(this.tpmKeyStore, this.tokenPassword.getPassword());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            logger.info("Loaded {} key managers", keyManagers.length);

            KeyStore trustStore = getTrustStore(trustStorePath);

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
     * Calls createCertRequest() to create a CSR and returns it in DER format
     * @param alias the keystore alias with the keypair for which the csr is generated
     * @return a CSR in DER format
     * @throws AcmeTpmException
     */
    public byte[] getCertRequestDER(String alias) throws AcmeTpmException {
        logger.info("Generating CSR for alias " + alias);
        try {
            PKCS10CertificationRequest request = createCertRequest(alias);
            return request.getEncoded();
        } catch (AcmeTpmException | IOException e) {
            throw new AcmeTpmException("Error creating signing request for alias " + alias + ": " + e.getMessage());
        }
    }
    
    /**
     * Calls createCertRequest() to create a CSR and returns it in PEM format
     * @param alias the keystore alias with the keypair for which the csr is generated
     * @return a CSR in PEM format
     * @throws AcmeTpmException
     */
    public String getCertRequestPEM(String alias) throws AcmeTpmException {
        logger.info("Generating CSR for alias " + alias);
        try {
            PKCS10CertificationRequest request = createCertRequest(alias);
            StringWriter sw = new StringWriter();
            JcaPEMWriter writer = new JcaPEMWriter(sw);
            writer.writeObject(request);
            writer.close();
            return sw.toString();
        } catch (AcmeTpmException | IOException e) {
            throw new AcmeTpmException("Error creating signing request for alias " + alias + ": " + e.getMessage());
        }
    }

    /**
     * Generates a PKCS10 Certificate request and returns it to the caller.
     * @param alias - the alias corresponding to the keypair for which the request will be generated.
     * @return Signed Certificate Request
     * @throws AcmeTpmException
     */
    // TODO: Update so that the profile is correct unless EJBCA will do that for us
    private PKCS10CertificationRequest createCertRequest(String alias) throws AcmeTpmException {
        KeyPair keyPair;
        X500Name distinguishedName = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Self").build();
        try {
            keyPair = getKeyPair(alias);
            PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                distinguishedName,
                keyPair.getPublic()
                ).build(new JcaContentSignerBuilder(CERT_SIG_ALG).build(keyPair.getPrivate()));
            return request;
        } catch (OperatorCreationException e) {
            throw new AcmeTpmException("Unable to create certificate request for " + alias + ": " + e.getMessage());
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
     * getKeyPair returns the keypair for an alias if it exists. It will return a
     * keypair or raise an Exception.
     *
     * @return The KeyPair associated with the user account on the ACME server.
     * @throws AcmeTpmException
     */
    public KeyPair getKeyPair(String alias) throws AcmeTpmException {
        try {
            // Look for the KeyPair in the Token Keystore
            if (this.tpmKeyStore.containsAlias(alias)) {
                logger.debug("Found keyPair alias " + alias + " in Keystore, retrieving");
                PublicKey pubKey = this.tpmKeyStore.getCertificate(alias).getPublicKey();

                PrivateKey prvKey = ((PrivateKeyEntry) this.tpmKeyStore.getEntry(alias,
                        this.tokenPassword)).getPrivateKey();

                logger.debug("Completed loading userKeyPair from keystore - returning.");
                
                return new KeyPair(pubKey, prvKey);
            } else {
                throw new AcmeTpmException("Unable to find keypair for " + alias);
            }
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException e) {
            throw new AcmeTpmException(e.getMessage());
        }
    }    

    /**
     * Call this function when an updated certificate is obtained from the ACME server, 
     * or when the user auth certificate is updated out of band. 
     * It update the keypair in the token associated with the alias passed in.
     * @param alias the alias of the keypair to update
     * @param certHolder a certificateHolder object to be converted into a certificate and stored in the token.
     */
    public void updateCertificate(String alias, String certPEM) throws AcmeTpmException {
        // Accept a certificate and update the pkcs11 store with the cert in the right
        // alias
        try {
            // Convert the String to a Certificate
            Certificate cert = pemToCert(certPEM);
            
            // fetch the keystore entry
            if (tpmKeyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
                PrivateKeyEntry currentEntry = (PrivateKeyEntry) tpmKeyStore.getEntry(alias, tokenPassword);
                PrivateKeyEntry newEntry = new PrivateKeyEntry(currentEntry.getPrivateKey(), new Certificate[] {cert});
                tpmKeyStore.setEntry(alias, newEntry, tokenPassword);
            } else {
                try {
                    String entryType = tpmKeyStore.getEntry(alias, tokenPassword).getClass().getName();
                    throw new AcmeTpmException("Keystore entry " + alias + " is not the correct type. Expected PrivateKeyEntry, but got " + entryType);
                } catch (Exception e) {
                    throw new AcmeTpmException("Keystore entry " + alias + " is not the correct type, and we were unable to determine its type.");
                }
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new AcmeTpmException("Unable to update certificate for keystore alias " + alias + ": " + e.getMessage());
        }

    }

    /**
     * gets the Trust store containing the Issuing CA Certificates. Used by getSSLContext.
     * @return the Keystore representing the trust store containing the CA public key certificates
     * @throws AcmeTpmException if the keystore does not exist or cannot be loaded.
     */
    private KeyStore getTrustStore(Path ejbcaTrustStore) throws AcmeTpmException {
        KeyStore keystore;
        try {
            char[] trustStorePassword = "trustme".toCharArray(); 
            keystore = KeyStore.getInstance("PKCS12");

            final File keystoreFile = ejbcaTrustStore.toFile();

            logger.info("Loading keystore from file {}", keystoreFile);
            InputStream keystoreStream = new FileInputStream(keystoreFile);

            keystore.load(keystoreStream, trustStorePassword);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new AcmeTpmException(e.getMessage());
        }
        return keystore;
    }

    /**
     * Returns information related to keys 
     * @param alias
     * @return
     * @throws AcmeTpmException
     */
    public HashMap<String, String> getKeyInfo(String alias) throws AcmeTpmException {
        try {
            var keyInfoHashMap = new HashMap<String, String>();
            if (this.tpmKeyStore.containsAlias(alias)) {
                var ksEntry = this.tpmKeyStore.getEntry(alias, tokenPassword);
                var attributes = ksEntry.getAttributes();
                System.out.println("Key Alias: " + alias);
                for (var attribute: attributes) {
                    keyInfoHashMap.put(attribute.getName(), attribute.getValue());
                }
                
                return keyInfoHashMap;
            } else {
                throw new AcmeTpmException(alias + "  is not a managed domain.");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new AcmeTpmException("Unable to access key for " + alias + ": " + e.getMessage());
        }
    }

    /**
     * Converts an X509Certificate in PEM format to an X509Certificate
     * @param certPEM a cert in PEM format
     * @return and X509Certificate object
     * @throws AcmeTpmException
     */
    private X509Certificate pemToCert(String certPEM) throws AcmeTpmException {
        try (PEMParser parser = new PEMParser(new StringReader(certPEM))) {
            JcaX509CertificateConverter x509Converter = new JcaX509CertificateConverter().setProvider(bcProvider);
            return x509Converter.getCertificate((X509CertificateHolder) parser.readObject());
        } catch (Exception e) {
            throw new AcmeTpmException("Unable to convert provided string to x509Certificate" + e.getMessage());
        }
    }



}
