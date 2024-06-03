package gov.dot.faa.ang.idms.acmetpm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.HashMap;

public class PropLoader {
    public static HashMap<String,String> props = new HashMap<String,String>();
    public PropLoader(Path propFile) throws AcmeTpmException {
                Properties defaultProps = new Properties();
        try{
            InputStream in = Files.newInputStream(propFile);
            defaultProps.load(in);
            in.close();
        } catch (IOException ex) {
            throw new AcmeTpmException(
                "Unable to open properties file. Expecting it at " + propFile.toString()
                );
        }

        for (String key: defaultProps.stringPropertyNames()) {
            props.put(key, defaultProps.getProperty(key, null));
        }




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
