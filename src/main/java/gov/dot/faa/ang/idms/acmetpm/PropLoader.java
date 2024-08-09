package gov.dot.faa.ang.idms.acmetpm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class PropLoader {
    public static Properties props;
    private static Path propFileLocation = Path.of("etc", "acmetpm", "acmetpm.properties");

    public PropLoader() throws AcmeTpmException {
        props = new Properties();
        setDefaultProperties();
        initialize(propFileLocation);
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
        Path filesystemRoot = null;
        FileSystem fileSystem = FileSystems.getDefault();
        var roots = fileSystem.getRootDirectories();
        for (var root: roots) {
            if (Files.exists(root.resolve(propFile))) {
                filesystemRoot = root;
            }
        }

        if (filesystemRoot == null) {
            throw new AcmeTpmException("Can't locate a filesystem with the property file.");
        }

        try{
            InputStream in = Files.newInputStream(filesystemRoot.resolve(propFile));
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
        // TODO: This should be an optional
        if (props.containsKey(propName)) {
            return props.getProperty(propName);
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
}
