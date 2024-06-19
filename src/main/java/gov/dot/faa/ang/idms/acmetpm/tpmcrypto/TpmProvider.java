package gov.dot.faa.ang.idms.acmetpm.tpmcrypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.String;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;

import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

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

    private void updateCertificate(String alias, X509CertificateHolder certHolder) {
        // Accept a certificate and update the pkcs11 store with the cert in the right
        // alias

    }

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

}
