package gov.dot.faa.ang.idms.acmetpm.tpmcrypto;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;

import java.util.HashMap;
import java.util.HexFormat;

import org.pkcs11.jacknji11.*;
import org.pkcs11.jacknji11.jna.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class providing access to the PKCS11 primitives. Needed only for pkcs11 path
 * Example paths: 
 * token: "pkcs11:model=NitroTPM;manufacturer=AMZN;serial=0000000000000000;token=label"
 * private key: "pkcs11:model=NitroTPM;manufacturer=AMZN;serial=0000000000000000;token=label;id=%75%73%65%72%4B%65%79%50%61%69%72;type=private"
 * public key: "pkcs11:model=NitroTPM;manufacturer=AMZN;serial=0000000000000000;token=label;id=%75%73%65%72%4B%65%79%50%61%69%72;object=userKeyPair;type=cer"
 */
public class UtilPKCS11 {

    private static final Logger logger = LoggerFactory.getLogger(UtilPKCS11.class);

    PropLoader props = new PropLoader();
    private final String label = props.getProp("token.label");
    private final String p11LibraryPath = props.getProp("token.libraryPath");
    private long acmeSlotID = 0;
    private HashMap<String, String> pathElements = new HashMap<>();

    /**
     * Constructer
     * @param Accepts a string representing the key ID
     */
    public UtilPKCS11(String keyIDString) throws AcmeTpmException {
        initializeLibrary();
        acmeSlotID = acmeSlot();
        if (acmeSlotID != 0) {
            pathElements = getPKCS11PathElements(keyIDString);
        } else {
            throw new AcmeTpmException("Unable to find token for acme. Expecting label " + this.label + ".");
        }
    }

    /**
     * Return the pkcs11 path URLs for the keypair
     * 
     * @return properly formatted pkcs11 paths to include in apache configuration files
     */
    public HashMap<String,String> getPaths() {
        // configMap.put(apachePrivKeyConfigKey, pkcs11KeyPath);
        // configMap.put(apacheCertConfigKey, pkcs11CertPath);
        HashMap<String, String> paths = new HashMap<>();

        // Build keyPath
        StringBuilder keyPathBuilder = new StringBuilder();
        keyPathBuilder.append("pkcs11:");
        keyPathBuilder.append("model="+ pathElements.get("model") + ";");
        keyPathBuilder.append("manufacturer=" + pathElements.get("manufacturer") + ";");
        keyPathBuilder.append("serial=" + pathElements.get("serial") + ";");
        keyPathBuilder.append("token=" + pathElements.get("token") + ";");
        keyPathBuilder.append("id=" + pathElements.get("id") + ";");
        keyPathBuilder.append("type=" + pathElements.get("keyType"));
        paths.put("SSLCertificateKeyFile", keyPathBuilder.toString());


        // Build certPath
        StringBuilder certPathBuilder = new StringBuilder();
        certPathBuilder.append("pkcs11:");
        certPathBuilder.append("model="+ pathElements.get("model") + ";");
        certPathBuilder.append("manufacturer=" + pathElements.get("manufacturer") + ";");
        certPathBuilder.append("serial=" + pathElements.get("serial") + ";");
        certPathBuilder.append("token=" + pathElements.get("token") + ";");
        certPathBuilder.append("id=" + pathElements.get("id") + ";");
        certPathBuilder.append("object=" + pathElements.get("object") + ";");
        certPathBuilder.append("type=" + pathElements.get("certType"));
        paths.put("SSLCertificateFile", certPathBuilder.toString());

        return paths;

    }

    /**
     * Returns the data elements that must be assembled into the key and cert Path for apache
     * @param keyID the identifier of the key
     * @return a hashmap containing the elements of the keypath based on the token
     */
    private HashMap<String,String> getPKCS11PathElements(String keyID) {
        HashMap<String, String> pathElements = new HashMap<>();

        CK_TOKEN_INFO ckTokenInfo = new CK_TOKEN_INFO();
        CE.GetTokenInfo(acmeSlotID, ckTokenInfo);

        // get the data from tokenInfo, 
        // stripping off the trailing spaces because the fields are fixed size
        pathElements.put("model", stripSpaces(ckTokenInfo.model));
        pathElements.put("manufacturer", stripSpaces(ckTokenInfo.manufacturerID));
        pathElements.put("serial", stripSpaces(ckTokenInfo.serialNumber));
        pathElements.put("token", stripSpaces(ckTokenInfo.label));

        // ID is the the numeric hex of the keyID with "%" before each character.
        HexFormat idFormat = HexFormat.ofDelimiter("%");
        String hexString = "%" + idFormat.formatHex(keyID.getBytes());
        pathElements.put("id", hexString);

        // Some static strings
        pathElements.put("object", "userKeyPair");
        pathElements.put("certType", "cert");
        pathElements.put("keyType", "private");
        return pathElements;
    }

    /**
     * This function strips the spaces from the fixed length strings returned by the PKCS11 library
     * @param original byte[]
     * @returns byte[] with leading and trailing spaces removed
     */
    private String stripSpaces(byte[] original) {
        return new String(original).strip();
    }

    private void initializeLibrary() {
        try {
            C.NATIVE = new JNA(p11LibraryPath);
            CE.Initialize();
        } catch (CKRException e) {
            logger.debug("Ignoring non-fatal error CRYPTOKI_ALREADY_INITIALIZED");
        }
    }

    private long acmeSlot() {
        // Get list of slots
        long[] slotList = CE.GetSlotList(true);

        // Iterate through the slots
        CK_SLOT_INFO cksInfo = new CK_SLOT_INFO();
        for (long slot: slotList) {
            CE.GetSlotInfo(slot, cksInfo);
            if (stripSpaces(cksInfo.slotDescription).equals(label)) {
                return slot;
            }
        }
        return 0;
    }


}
