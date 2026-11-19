package gov.dot.faa.ang.idms.acmetpm.crypto;

import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

public class ServerCertRequestBuilder {
    private static final Logger logger = LoggerFactory.getLogger(ServerCertRequestBuilder.class);
    
    private PKCS10CertificationRequest request;


    // These next two should be properties
    private static final String CERT_SIG_ALG = "SHA256withECDSA";
    private static final String MED_DEV_HW_OID = "1.3.27.16.1.1.0.8";

    public ServerCertRequestBuilder(String hostname, KeyPair keyPair) throws AcmeTpmException {
        var subjectName = getX500Name(hostname);

        var requestExtensions = new ExtensionsGenerator();
        requestExtensions.addExtension(getCertPoliciesExtension());
        requestExtensions.addExtension(getSubjectAlternativeNamesExtension(hostname));

        try {
            request = new JcaPKCS10CertificationRequestBuilder(
                subjectName,
                keyPair.getPublic()
            )
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, requestExtensions.generate())
            .build(new JcaContentSignerBuilder(CERT_SIG_ALG).build(keyPair.getPrivate()));
        } catch (OperatorCreationException e) {
            throw new AcmeTpmException("Unable to generate server Certification Request for: " + hostname);
        }
        

    }

    public PKCS10CertificationRequest getRequest() {
        return request;
    }

    private X500Name getX500Name(String hostname) {
        var distinguishedNameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        distinguishedNameBuilder.addRDN(BCStyle.CN, hostname);
        var distinguishedName = distinguishedNameBuilder.build();

        logger.debug("Built SubjectDN of {}", distinguishedName);
        return distinguishedName;
    }

    private Extensions getSubjectAlternativeNamesExtension(String hostnameOrIP) throws AcmeTpmException {
        try {
            var subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, hostnameOrIP));
            var sanExtensionGenerator = new ExtensionsGenerator();
            sanExtensionGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
            return sanExtensionGenerator.generate();
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to generate SAN for UserCertRequest: " + e.getLocalizedMessage());
        }
    }

    private Extensions getCertPoliciesExtension() throws AcmeTpmException {
        var idmsCertPolicies = new CertificatePolicies(
            new PolicyInformation(new ASN1ObjectIdentifier(MED_DEV_HW_OID))
        );

        var extGen = new ExtensionsGenerator();
        try {
            extGen.addExtension(Extension.certificatePolicies, false, idmsCertPolicies);
            return extGen.generate();
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to generate certificate Policy Extension.");
        }
    }
}
