package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

import java.util.ArrayList;

import net.augeas.Augeas;

public class ApacheConfigReader {
    private static final String DEFAULT_CONFIG_ROOT = "/etc/httpd";
    private static final String AUGEAS_ROOT = "/files" + DEFAULT_CONFIG_ROOT;
    private static final String SSL_LOAD_MODULE_PATH = AUGEAS_ROOT +
            "//directive[. =~ regexp(\"LoadModule.*\")][arg = \"ssl_module\"]";
    private static final String VIRT_HOST_LIST_STRING = AUGEAS_ROOT + 
            "//VirtualHost/directive[\"SSLEngine\"]/arg[\"on\"]/../../arg";

    private Augeas augInstance;
    private ArrayList<ApacheVirtualHostConfig> configs;

    public ApacheConfigReader() {
        this.augInstance = new Augeas();
        if (sslModuleLoaded()) {
            vHostList.addAll(getSSLVirtualHosts());
        }
    }

    public ArrayList<ApacheVirtualHostConfig> getConfigs() {
        return configs;
    }

    public boolean sslModuleLoaded() {
        return this.augInstance.exists(SSL_LOAD_MODULE_PATH);
    }

    private ArrayList<String> getSSLVirtualHosts() {
        ArrayList<String> hostIdList = new ArrayList<String>();
        for (String path: this.augInstance.match(VIRT_HOST_LIST_STRING)){
            hostIdList.add(this.augInstance.get(path));
        }
        return hostIdList;
    }

    
    public void GetSSLPathsForVhost(String vHost) {

    }
}
