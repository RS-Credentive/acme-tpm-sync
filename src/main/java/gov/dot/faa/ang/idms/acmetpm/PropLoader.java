package gov.dot.faa.ang.idms.acmetpm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
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
        props.put("token.label", "label");
        props.put("token.password", "myuserpin");
        props.put("token.libraryPath", "/usr/lib64/pkcs11/libtpm2_pkcs11.so");
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
        return props.get(propName);
    }

    public String[] getEjbcaServers() throws AcmeTpmException {
        if (props.keySet().contains("ejbca.addresses")) {
            return props.get("ejbca.addresses").split("|");
        } else {
            throw new AcmeTpmException("Property file does not contain Server hostnames.");
        }

    }

    public String getTokenPassword() throws AcmeTpmException {
        if (props.keySet().contains("token_password")) {
            return props.get("token_password");
        } else {
            throw new AcmeTpmException("No token password in props file.");
        }
    }

}
