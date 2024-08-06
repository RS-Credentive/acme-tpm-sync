package gov.dot.faa.ang.idms.acmetpm;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class PropLoader {
    public static Properties props;
    private static Path propFileLocation = Path.of("etc", "acmetpm", "acmetpm.properties");

    public PropLoader() throws AcmeTpmException {
        if (props.size() == 0) {
            setDefaultProperties();
            initialize(propFileLocation);
        }
    }

    private static final void setDefaultProperties() throws AcmeTpmException {
        try {
            var defaultPropStream = PropLoader.class.getResourceAsStream("/default.properties");
            props.load(defaultPropStream);
        } catch (IOException e) {
            throw new AcmeTpmException("Unable to load default properties from resource");
        }
    }

    private static void initialize(Path propFile) throws AcmeTpmException {
        try{
            InputStream in = Files.newInputStream(propFile);
            props.load(in);
            in.close();
        } catch (IOException ex) {
            throw new AcmeTpmException(
                "Unable to open properties file. Expecting it at " + propFile.toString()
                );
        }
    }

    public String getTokenPassword() throws AcmeTpmException {
        return getProp("token.password");
    }

    public String getProp(String propName) throws AcmeTpmException {
        if (props.containsKey(propName)) {
            return props.getProperty(propName);
        } else {
            throw new AcmeTpmException("No property named " + propName);
        }
    }

    public void setProp(String propName, String value) {
        props.put(propName, value);
    }

    public boolean hasProp(String propName) {
        return props.containsKey(propName);
    }
}
