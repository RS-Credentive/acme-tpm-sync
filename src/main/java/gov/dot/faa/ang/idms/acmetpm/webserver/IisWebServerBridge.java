package gov.dot.faa.ang.idms.acmetpm.webserver;

import module java.base;

import gov.dot.faa.ang.idms.acmetpm.webserver.iis.IisConfigReader;
import org.json.*;

/**
 * IisWebServerBridge
 */
public final class IisWebServerBridge implements WebServerBridge {
    public record SiteConfig(String siteName, String protocol, String certificateStoreName) {
        public static SiteConfig fromJson(String json) {
            // Implement JSON parsing logic here to create a SiteConfig instance from the provided JSON string.
            var jsonObject = new JSONObject(json);
            
            if (!jsonObject.has("siteName") || !jsonObject.has("protocol") || !jsonObject.has("certificateStoreName")) {
                throw new IllegalArgumentException("JSON must contain siteName, protocol, and certificateStoreName fields.");
            }
            
            return new SiteConfig(
                jsonObject.getString("siteName"),
                jsonObject.getString("protocol"),
                jsonObject.getString("certificateStoreName")
            );
        }
    }

    public List<SiteConfig> getSiteConfig(String siteName) {
        var siteConfigList = new ArrayList<SiteConfig>();

        try {
            IisConfigReader.readConfig();
            
        } catch (Throwable e) {
            throw new RuntimeException("Failed to read IIS configuration", e);
        }

        return siteConfigList;
    }
}
