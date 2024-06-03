package gov.dot.faa.ang.idms.acmetpm.tpmprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.String;

import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpm;
import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

import org.slf4j.Logger;

public class TpmProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(TpmProvider.class);
    private static final String TPM_PKCS11_CONFIG = AcmeTpm.TPM_JCA_CONFIG.toString();

    public static Provider tpmProvider;
    private static KeyStore tpmKeyStore;

    public TpmProvider(String tokenPassword) throws AcmeTpmException {
        try {
            tpmProvider = Security.getProvider("SunPKCS11").configure(TPM_PKCS11_CONFIG);
            Security.addProvider(tpmProvider);
            tpmKeyStore = KeyStore.getInstance("PKCS11-TpmAccelerator", tpmProvider);
            KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(tokenPassword.toCharArray());
            tpmKeyStore.load(null, pp.getPassword());     
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            throw new AcmeTpmException(ex.getMessage());
        }
    }

    public Provider getProvider() {
        return tpmProvider;
    }

    public Key getUserKeyHandle() {
        // Start Here
    }

    private KeyStore getTrustStore() throws AcmeTpmException {
        KeyStore keystore;
        try {
            String trustStorePassword = AcmeTpm.CLIENT_KEY_STORE_PIN;
            keystore = KeyStore.getInstance("PKCS12");

            final File keystoreFile = AcmeTpm.EJBCA_TRUSTSTORE.toFile();

            InputStream keystoreStream;

            LOGGER.info("Loading keystore from file {}", keystoreFile);
            keystoreStream = new FileInputStream(keystoreFile);


            keystore.load(keystoreStream, trustStorePassword.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new AcmeTpmException(e.getMessage());
        }
        return keystore;
    }

    public SSLContext getSSLContext() throws AcmeTpmException {
        LOGGER.info("Loading Client Keystore using PKCS11, with config {}", TPM_PKCS11_CONFIG);
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

            KeyStore tpmKeyStore = KeyStore.getInstance("PKCS11-TpmAccelerator", tpmProvider);

            KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(AcmeTpm.CLIENT_KEY_STORE_PIN.toCharArray());
            tpmKeyStore.load(null, pp.getPassword());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(tpmKeyStore, AcmeTpm.CLIENT_KEY_STORE_PIN.toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            LOGGER.info("Loaded {} key managers", keyManagers.length);

            KeyStore trustStore = getTrustStore();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            TrustManager[] trustManagers = tmf.getTrustManagers();

            sslContext.init(keyManagers, trustManagers, new java.security.SecureRandom());
            return sslContext;
        } catch (AcmeTpmException | CertificateException | IOException | KeyManagementException | KeyStoreException |  
                    NoSuchAlgorithmException | UnrecoverableKeyException  e) {
            throw new AcmeTpmException(e.getMessage());
        }
    }

}
