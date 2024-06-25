package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import net.augeas.Augeas;

/** 
 * Class providing programatic access to the contents of an Apache Configuration 
*/
public class ApacheConfigReader {
    // Constants for Xpath building
    private static final String DEFAULT_CONFIG_ROOT = "/etc/httpd"; // This should be a property.
    private static final String AUGEAS_ROOT = "/files" + DEFAULT_CONFIG_ROOT;
    private static final String SSL_LOAD_MODULE_PATH = AUGEAS_ROOT +
        "//directive[. =~ regexp(\"LoadModule.*\")][arg = \"ssl_module\"]";
    private static final String VIRT_HOST_LIST_PATH = AUGEAS_ROOT + 
        "//VirtualHost/directive[\"SSLEngine\"]/arg[\"on\"]/../../arg";
    private static final String SSL_SERVER_CERT_PATH = AUGEAS_ROOT + 
        "//VirtualHost[arg = \"{{VHOST}}\"]/directive[\"SSLCertificateFile\"]/arg";
    private static final String SSL_PRIVATE_KEY_PATH = AUGEAS_ROOT + 
        "//VirtualHost[arg = \"{{VHOST}}\"]/directive[\"SSLCertificateKeyFile\"]/arg";

    // Inner class for keeping a cert/key pair
    public record ApacheVirtualHostConfig(
        String sslCertificatePath,
        String sslPrivateKeyPath
    ) {}

    // HashMap for supported configs. Key is Virtual Host name, value is a the inner class just above.
    private HashMap<String, ApacheVirtualHostConfig> configs = new HashMap<>();

    // The instance of the augeas object. Because this can be slow to initialize, we create and reuse it.
    private final Augeas augInstance;
    
    /** Constructor */
    public ApacheConfigReader() {
        // create the instance
        this.augInstance = new Augeas();

        // check and see if SSL module is loaded, and if so get the list of Virtual Hosts (vHosts) using SSL
        ArrayList<String> vHostList = new ArrayList<>();
        if (sslModuleLoaded()) {
            vHostList.addAll(getSSLVirtualHosts());
        }

        // for each of the vHosts, get the key/certificate paths from the config
        for (String host: vHostList) {
            this.configs.put(host, getConfigForHost(host));
        }

    }

    /**
     * Returns a set containing the names of all of the vHosts discovered by augeas
     * @return Set<String> containing a list of Virtual Host ids 
     */
    public Set<String> getVHosts() {
        return this.configs.keySet();
    }

    /**
     * Returns true if the Virtual Host ID passed in has been discovered, or false otherwise
     * @param vHost - the Virtual Host name ("hostname:port") we are checking for
     * @return true if the host is configured, false if not
     */
    public boolean vHostExists(String vHost) {
        return this.configs.containsKey(vHost);
    }

    /**
     * Returns the path identifying the location of the private key for a Virtual Host
     * @param vHost the Virtual Host for which we want the location of the private key
     * @return the location of the private key from the configuration file
     */
    public final String getKeyLocationForVHost(String vHost) {
        return this.configs.get(vHost).sslPrivateKeyPath;
    }

    /**
     * Returns the path identifying the location of the public key certificate for a Virtual Host
     * @param vHost the Virtual Host for which we want the location of the public key certificate
     * @return the location of the public key certificate from the configuration file
     */
    public final String getCertLocationforVHost(String vHost) {
        return this.configs.get(vHost).sslCertificatePath;
    }

    /**
     * Returns a boolean indicating whether the apache "mod_ssl" module is loaded in the configuration.
     * Run by the initializer for the ApacheConfigReader Object.
     * 
     * @return true if mod_ssl is loaded, false if not
     */
    private boolean sslModuleLoaded() {
        return this.augInstance.exists(SSL_LOAD_MODULE_PATH);
    }

    /**
     * Inspects the configuration and returns a list of virtual hosts configured on the apache server.
     * Run by the initializer for the ApacheConfigReader Object
     * 
     * @return an ArrayList of Strings containing the virtual host names (hostname:port)
     */
    private ArrayList<String> getSSLVirtualHosts() {
        ArrayList<String> hostIdList = new ArrayList<>();
        for (String path: this.augInstance.match(VIRT_HOST_LIST_PATH)){
            hostIdList.add(this.augInstance.get(path));
        }
        return hostIdList;
    }
    
    /**
     * Private method that discovers the private key and public key certificate locations in the configuration files 
     * for a virtual host. Run by the initializer for the ApacheConfigReader Object
     * 
     * @param vHost - the Virtual Host for which we want the location of the private key and public key certificate
     * @return an ApacheVirtualHostConfig object containing the private key and public key certificate paths
     */
    private ApacheVirtualHostConfig getConfigForHost(String vHost) {
        String sslCertificateConfigPath = SSL_SERVER_CERT_PATH.replace("{{VHOST}}", vHost);
        String sslCertificateLocation = "";

        String sslPrivateKeyConfigPath = SSL_PRIVATE_KEY_PATH.replace("{{VHOST}}", vHost);
        String sslPrivateKeyLocation = "";

        if (augInstance.exists(sslCertificateConfigPath)) {
            sslCertificateLocation = augInstance.get(sslCertificateConfigPath);
        }

        if (augInstance.exists(sslPrivateKeyConfigPath)) {
            sslPrivateKeyLocation =  augInstance.get(sslPrivateKeyConfigPath);
        }

        return new ApacheVirtualHostConfig(sslCertificateLocation, sslPrivateKeyLocation);
    }

    public void updateConfigForHost(String vHost, String certPath, String keyPath) {
        String sslCertificateConfigPath = SSL_SERVER_CERT_PATH.replace("{{VHOST}}", vHost);
        String sslPrivateKeyConfigPath = SSL_PRIVATE_KEY_PATH.replace("{{VHOST}}", vHost);
        augInstance.set(sslCertificateConfigPath, certPath);
        augInstance.set(sslPrivateKeyConfigPath, keyPath);
        augInstance.save();
    }
}
