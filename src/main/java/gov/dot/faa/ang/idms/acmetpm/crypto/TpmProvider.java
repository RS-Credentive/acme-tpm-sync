package gov.dot.faa.ang.idms.acmetpm.crypto;

import module java.base;

import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;
import gov.dot.faa.ang.idms.acmetpm.crypto.bridge.Pkcs11TpmBridge;


/** 
 * Class to encapsulate cryptographic functionality for a TPM-backed PKCS11 keystore for ACME
 * 
 * @author robert.sherwood@credentive.com
 * 
 */
public class TpmProvider {
    private static final PropLoader props = new PropLoader();
    private static final Logger logger = LoggerFactory.getLogger(TpmProvider.class);
    private static final String KEYPAIR_ALGORITHM = "EC";
    private static final String CERT_SIG_ALG = "SHA256withECDSA";
    private static final String EC_PARAM_SPEC = "secp256r1";
    

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
            logger.debug("Constructing Token Provider");

            logger.debug("Loading BouncyCastle Provider");
            bcProvider = new BouncyCastleProvider();
            Security.addProvider(bcProvider);

            logger.debug("Loading TPM PKCS11 Provider");
            logger.debug("Loading SunPKCS11 configuration from {}", jcaConfigFilePath);
            tpmProvider = Security.getProvider("SunPKCS11").configure("/" + jcaConfigFilePath);
            Security.addProvider(tpmProvider);

            logger.debug("Loading Keystore from TPM backed token.");
            this.tpmKeyStore = KeyStore.getInstance("PKCS11-TpmAccelerator", tpmProvider);
            this.tokenPassword = new KeyStore.PasswordProtection(tokenPassword.toCharArray());
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
                String USER_ALIAS = props.getProp("token.userAlias");
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
     * Returns a list of all aliases managed in the TPM.
     * @return ArrayList<String>
     * @throws AcmeTpmException
     */
    public ArrayList<String> getAliases() throws AcmeTpmException {
        try {
            var aliases = new ArrayList<String>();
            var aliasEnum = this.tpmKeyStore.aliases();
            while (aliasEnum.hasMoreElements()) {
                var nextalias = aliasEnum.nextElement();
                if (nextalias.equals("userKeyPair")) {
                } else {
                    aliases.add(nextalias);
                }
            }
            return aliases;
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Error enumerating key aliases: " + e.getMessage());
        }
    }

    /**
     * Returns true if the alias is managed in the TPM backed token, or false if it is not. We check for the alias in the list of keystor aliases.
     * @param String representing the alias name for the managed key
     * @return true if the keystore contains the alias, false if it does not.
     * @throws AcmeTpmException
     */
    public boolean hasAlias(String alias) throws AcmeTpmException {
        try {
            return this.tpmKeyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Unable to check for alias " + alias + ". Error: " + e.getMessage());
        }
    }

    /**
     * Parses the certificate associated with an alias and returns the expiration date.
     * @param alias to check
     * @return Date object corresponding to the certificate's expiration date.
     * @throws AcmeTpmException
     */
    public Date aliasCertExpiration(String alias) throws AcmeTpmException {
        if (hasAlias(alias)) {
            try {                
                X509Certificate aliasCert = (X509Certificate)this.tpmKeyStore.getCertificate(alias);
                return aliasCert.getNotAfter();
            } catch (KeyStoreException e) {
                throw new AcmeTpmException("Error attempting to determine expiration date for " + alias + ": " + e.getMessage());
            }
        } else {
            throw new AcmeTpmException(alias + " is not a valid alias.");
        }
    }

    /**
     * Generates and stores a key pair for an alias. If the keypair already exists, return silently.
     * 
     * @param alias the dns name for the host
     * @return The keypair for that alias if it exists in the keystore
     * @throws AcmeTpmException if the attempt to retrieve or create the keypair fails
     */
    public void addAlias(String alias) throws AcmeTpmException {
        logger.debug("Calling getaliasKeyPair for {}", alias);
        try {
            if (this.tpmKeyStore.containsAlias(alias)) {
                logger.debug("Keypair for {} already exists.", alias);
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
     * Delete an alias and its associated keypair
     * @param aliasName the name of the alias of the keypair to delete.
     * @throws AcmeTpmException
     */
    public void deleteAlias(String aliasName) throws AcmeTpmException {
        try {
            if (this.tpmKeyStore.containsAlias(aliasName)) {
                logger.debug("Alias " + aliasName + " exists. Deleting.");
                this.tpmKeyStore.deleteEntry(aliasName);                
            } else {
                logger.debug("Alias does not exist.");
            }
        } catch (KeyStoreException e) {
            throw new AcmeTpmException("Unable to delete keypair for " + aliasName + e.getMessage());
        }
    }

    /**
     * Returns the pkcs11 paths for a private key and certificate pair stored in the TPM backed token
     * @param The alias name corresponding the the keypair alias
     * @return a Hashmap containing the private and public pkcs11 paths for the private and public keys.
     */
    public HashMap<String, String> getPkcs11Paths(String alias) throws AcmeTpmException {
        // Initialize the PKCS11 utility
        var pkcs11Util = new Pkcs11TpmBridge(alias);

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
        logger.debug("Loading Client Keystore using PKCS11");
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(this.tpmKeyStore, this.tokenPassword.getPassword());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            logger.debug("Loaded {} key managers", keyManagers.length);

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
    public byte[] getCertRequestDER(String alias, String commonName, boolean includeBaseDN) throws AcmeTpmException {
        logger.debug("Generating CSR for alias " + alias);

        try {
            PKCS10CertificationRequest request = createCertRequest(alias, commonName, includeBaseDN);
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
    public String getCertRequestPEM(String alias, String commonName, boolean includeBaseDN) throws AcmeTpmException {
        logger.debug("Generating CSR for alias " + alias);
        try {
            PKCS10CertificationRequest request = createCertRequest(alias, commonName, includeBaseDN);
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
    private PKCS10CertificationRequest createCertRequest(String alias, String commonName, boolean includeBaseDN) throws AcmeTpmException {
        logger.debug("Attempting to build CSR for {}", alias);

        // Get the keys
        logger.debug("Getting the keys");
        KeyPair keyPair = getKeyPair(alias);

        if (alias == props.getProp("token.userAlias")) {
            logger.debug("Request for user Cert detected.");
            return new AccountCertificateRequestBuilder(keyPair).getRequest();
        }

        // If a null commonName is passed in, set the value to be the same as the alias.
        if (commonName == null) {
            logger.debug("No commonName passed in. Setting CN to alias, {}", alias);
            commonName = alias;
        }

        // Build the distinguished name 
        var distinguishedNameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        distinguishedNameBuilder.addRDN(BCStyle.CN, commonName);
        logger.debug("Built SubjectDN of {}", distinguishedNameBuilder.build().toString());

        // Build subjectAltName
        var subjectAlternativeName = new GeneralNamesBuilder().addName(new GeneralName(GeneralName.rfc822Name, alias)).build();
        logger.debug("Built SAN of {}", subjectAlternativeName.toString());

        // Add Cert Policy OID
        var medDevHwOID = "1.3.27.16.1.1.0.8";
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(medDevHwOID));
        CertificatePolicies certificatePolicies = new CertificatePolicies(policyInformation);

        try {
            PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                    distinguishedNameBuilder.build(),
                    keyPair.getPublic()
                )
                .addAttribute(Extension.subjectAlternativeName, subjectAlternativeName)
                .addAttribute(Extension.certificatePolicies, certificatePolicies)
                .build(new JcaContentSignerBuilder(CERT_SIG_ALG).build(keyPair.getPrivate()));
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
            logger.debug("Attempting to create new {}  keys with parameters {}", KEYPAIR_ALGORITHM, EC_PARAM_SPEC);
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
     * @param alias the desired alias for the keypair this should be either the USER_ALIAS, or the alias name identifying the web server or certificates.
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
    public void updateCertificatePEM(String alias, String certPEM) throws AcmeTpmException {
        // Convert the String to a Certificate
        Certificate cert = pemToCert(certPEM);
            
        updateCertificate(alias, cert);
    }

    /**
     * Call this function when an updated certificate is obtained from the ACME server, 
     * It update the keypair in the token associated with the alias passed in.
     * @param alias the alias of the keypair to update
     * @param certHolder a certificateHolder object to be converted into a certificate and stored in the token.
     */
    public void updateCertificate(String alias, Certificate certificate) throws AcmeTpmException {
        try {            
            // fetch the keystore entry
            if (tpmKeyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) {
                PrivateKeyEntry currentEntry = (PrivateKeyEntry) tpmKeyStore.getEntry(alias, tokenPassword);
                PrivateKeyEntry newEntry = new PrivateKeyEntry(currentEntry.getPrivateKey(), new Certificate[] {certificate});
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

            logger.debug("Loading keystore from file {}", keystoreFile);
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
                throw new AcmeTpmException(alias + "  is not a valid alias.");
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
