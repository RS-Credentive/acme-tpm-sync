package gov.dot.faa.ang.idms;

import java.security.Key;
import java.security.KeyPair;
import java.net.URI;

import org.shredzone.acme4j.Session;

import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;
import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

import gov.dot.faa.ang.idms.acmetpm.apacheconfig.ApacheConfigReader;
import java.nio.file.Path;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * 
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        // final String domainString = "test.faa.gov";
        // final String server = "Apache";
        // TpmProvider tpmProvider;
        // KeyPair userKeyPair;
        // KeyPair domainKeyPair;
        // IdmsAcmeProvider idmsAcmeProvider = new IdmsAcmeProvider();
        // System.out.println("Initializing tpmProvider");
        // try {
        // tpmProvider = new TpmProvider("myuserpin");
        // System.out.println("Initializing tpmProvider and Getting userKeyPair");
        // userKeyPair = tpmProvider.getUserKeyPair();
        // System.out.println("Getting Domain KeyPair");
        // domainKeyPair = tpmProvider.getDomainKeyPair(domainString);
        // Session ejbcaSession = new Session(new URI("TBD"), idmsAcmeProvider);
        // ejbcaSession.login(null, userKeyPair); // TODO fix

        // } catch (Exception e) {
        // System.out.println("Failed to get userKeyPair: " + e);
        // System.exit(1);
        // }

        ApacheConfigReader configReader = new ApacheConfigReader();

        if (configReader.sslModuleLoaded()) {
            System.out.println("Found SSL Config");
        } else {
            System.out.println("No SSl Config found");
        }

        for (String vHost : configReader.vHostList) {
            System.out.println(vHost);
        }


    }

    // private static void testPKCS11Keys() throws Exception {
    // final char[] sopin = "mysopin".toCharArray();
    // final char[] userpin = "myuserpin".toCharArray();
    // final String tokenLabel = "label";
    // final String TPM_PKCS11_CONFIG =
    // "/home/robert.ctr.sherwood/Projects/acmetpm/acmetpm.conf";
    // final String KEYPAIR_ALGORITHM = "EC";
    // final String EC_PARAM_SPEC = "secp256r1";
    // final String CERT_SIG_ALG = "SHA256withECDSA";
    // final String TEST_KEY_LABEL = "test";
    // final HexFormat hexFormat = HexFormat.ofDelimiter(":");

    // // Generate KeyPair
    // Provider bcProvider = new BouncyCastleProvider();
    // Security.addProvider(bcProvider);
    // Provider tpmProvider =
    // Security.getProvider("SunPKCS11").configure(TPM_PKCS11_CONFIG);
    // Security.addProvider(tpmProvider);
    // KeyStore tpmKeyStore = KeyStore.getInstance("PKCS11-TpmAccelerator",
    // tpmProvider);
    // tpmKeyStore.load(null, userpin);
    // KeyPairGenerator kpGen = KeyPairGenerator.getInstance(KEYPAIR_ALGORITHM,
    // tpmProvider);
    // kpGen.initialize(new ECGenParameterSpec(EC_PARAM_SPEC), new SecureRandom());
    // KeyPair keypair = kpGen.generateKeyPair();

    // System.out.println("Pub Key algorithm: " +
    // keypair.getPublic().getAlgorithm());

    // // Try to sign a certificate
    // String alias = TEST_KEY_LABEL;
    // try {
    // if (tpmKeyStore.containsAlias(alias)) {
    // throw new AcmeTpmException("KeyPair with alias " + alias + " already
    // exists");
    // } else {
    // // Generate self-signed certificate for keypair or Java won't recognize it.

    // X500Name distinguishedName = new
    // X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Self").build();

    // SubjectPublicKeyInfo pubKey =
    // SubjectPublicKeyInfo.getInstance(keypair.getPublic().getEncoded());

    // BigInteger serial = new BigInteger("1");

    // Date notBefore = Date.from(Instant.now());

    // Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(365)));

    // var simpleCS = new
    // JcaContentSignerBuilder(CERT_SIG_ALG).build(keypair.getPrivate());

    // System.out.println("Building CertBuilder");
    // X509v3CertificateBuilder ecCertBuilder = new X509v3CertificateBuilder(
    // distinguishedName, // Issuer NAme
    // serial, // Serial Number
    // notBefore, // notBefore - now
    // notAfter, // notAfter - 1 year
    // distinguishedName, // Subject Name
    // pubKey // Public Key
    // );

    // X509CertificateHolder simpleCH = ecCertBuilder.build(simpleCS);

    // X509Certificate simpleCert = new
    // JcaX509CertificateConverter().getCertificate(simpleCH);
    // System.out.println("CertHolder subjectPubKeyInfo: " +
    // hexFormat.formatHex(simpleCH.getSubjectPublicKeyInfo().getEncoded()));

    // System.out.println("Simple PubKey: " + simpleCert.getPublicKey());

    // System.out.println("Setting alias for private key and Self-signed Cert");
    // tpmKeyStore.setKeyEntry(alias, keypair.getPrivate(), userpin, new
    // X509Certificate[] { simpleCert });

    // }
    // } catch (KeyStoreException | AcmeTpmException | CertificateException e) {
    // // Delete the keys we created if we were unsuccessful.
    // System.out.println("Catching an Error");
    // System.out.println(e);

    // }
    // }
}
