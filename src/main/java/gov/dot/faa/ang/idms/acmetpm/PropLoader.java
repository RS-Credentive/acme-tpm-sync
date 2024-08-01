package gov.dot.faa.ang.idms.acmetpm;

import java.nio.file.Path;
import java.util.HashMap;

public class PropLoader {
    public static HashMap<String,String> props = new HashMap<String,String>();
    private static Path propFileLocation = Path.of(""); // What should this be?

    public PropLoader() throws AcmeTpmException {
        if (props.size() == 0) {
            initialize(propFileLocation);
        }
    }

    private static final void fakeInitialize() {
        // This is a fake method so I can use the PropLoader before determining the file location and other stuff
        props.put("ejbca.addresses", "10.23.4.193|10.27.33.94|10.22.65.8|10.22.65.4");
        props.put("ejbca.sessionUri", "https://10.22.65.12");
        props.put("token.label", "label");
        props.put("token.password", "myuserpin");
        props.put("token.libraryPath", "/usr/lib64/pkcs11/libtpm2_pkcs11.so");
        props.put("domains.renewalLimit", "90");
        props.put("token.userAlias","userKeyPair");
        props.put("token.truststore", "/home/robert.ctr.sherwood/Projects/idmsTrustStore.p12"); // where is this?
        props.put("token.jcaConfigFile", "/home/robert.ctr.sherwood/Projects/acmetpm.conf");
        props.put("acme.accountURL", null);
        props.put("acme.userEmail", "robert.ctr.sherwood@faa.gov");
    }

    private static void initialize(Path propFile) throws AcmeTpmException {
        fakeInitialize();
        // Properties defaultProps = new Properties();
        // try{
        //     InputStream in = Files.newInputStream(propFile);
        //     defaultProps.load(in);
        //     in.close();
        // } catch (IOException ex) {
        //     throw new AcmeTpmException(
        //         "Unable to open properties file. Expecting it at " + propFile.toString()
        //         );
        // }

        // for (String key: defaultProps.stringPropertyNames()) {
        //     props.put(key, defaultProps.getProperty(key, null));
        // }
    }

    public String getProp(String propName) {
        if (props.containsKey(propName)) {
            return props.get(propName);
        } else {
            return null;
        }
        
    }

    public void setProp(String propName, String value) {
        props.put(propName, value);
    }

    public boolean hasProp(String propName) {
        return props.containsKey(propName);
    }

    public String[] getEjbcaServers() throws AcmeTpmException {
        if (props.keySet().contains("ejbca.addresses")) {
            return props.get("ejbca.addresses").split("|");
        } else {
            throw new AcmeTpmException("Property file does not contain Server hostnames.");
        }

    }

    public String getTokenPassword() throws AcmeTpmException {
        if (props.keySet().contains("token.password")) {
            return props.get("token.password");
        } else {
            throw new AcmeTpmException("No token password in props file.");
        }
    }

}
