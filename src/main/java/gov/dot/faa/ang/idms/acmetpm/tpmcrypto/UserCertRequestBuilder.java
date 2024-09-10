package gov.dot.faa.ang.idms.acmetpm.tpmcrypto;

import gov.dot.faa.ang.idms.acmetpm.PropLoader;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

public class UserCertRequestBuilder {
    private static final Logger logger = LoggerFactory.getLogger(UserCertRequestBuilder.class);
    private static PropLoader props = new PropLoader();
    private static final String CERT_SIG_ALG = "SHA256withECDSA";
    private static final String MED_DEV_HW_OID = "1.3.27.16.1.1.0.8";
    private PKCS10CertificationRequest request;

    public UserCertRequestBuilder(KeyPair userKeyPair) throws AcmeTpmException {
        String userEmail = props.getProp("user.email");
        var subjectName = getX500Name(userEmail);

        var certPoliciesAttribute = new CertificatePolicies(
            new PolicyInformation(new ASN1ObjectIdentifier(MED_DEV_HW_OID))
        );

        

        try {
            request = new JcaPKCS10CertificationRequestBuilder(
                subjectName, 
                userKeyPair.getPublic()
            )
            .addAttribute(Extension.certificatePolicies, certPoliciesAttribute.toASN1Primitive())
            .build(new JcaContentSignerBuilder(CERT_SIG_ALG).build(userKeyPair.getPrivate()));
        } catch (Exception e) {
            throw new AcmeTpmException("Unable to build certRequest: " + e.getLocalizedMessage());
        }       
        
    }

    public PKCS10CertificationRequest getRequest() {
        return request;
    }

    private X500Name getX500Name(String userEmail) throws AcmeTpmException {
        var distinguishedNameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        distinguishedNameBuilder.addRDN(BCStyle.C, "US");
        distinguishedNameBuilder.addRDN(BCStyle.ST, "District of Columbia");
        distinguishedNameBuilder.addRDN(BCStyle.L, "Washington");
        distinguishedNameBuilder.addRDN(BCStyle.O, "Federal Aviation Administration");
        distinguishedNameBuilder.addRDN(BCStyle.CN, userEmail + "--" + getHostname());
        var distinguishedName = distinguishedNameBuilder.build();

        logger.debug("Built SubjectDN of {}", distinguishedName.toString());
        return distinguishedName;
    }

    private String getHostname() throws AcmeTpmException {
        try {
            return InetAddress.getLocalHost().getCanonicalHostName();
        } catch (Exception e) {
            throw new AcmeTpmException("Unable to determine hostname when trying to create the UserCertRequest: " + e.getLocalizedMessage());
        }
    }

}
