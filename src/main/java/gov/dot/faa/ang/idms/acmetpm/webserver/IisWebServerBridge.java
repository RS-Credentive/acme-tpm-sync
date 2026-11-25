package gov.dot.faa.ang.idms.acmetpm.webserver;

import module java.base;

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

    public static List<SiteConfig> getSiteConfig(String jsonConfig) {
        var siteConfigList = new ArrayList<SiteConfig>();

        try {
            var configArrayJSON = new JSONArray(jsonConfig);
            for (var configJSON : configArrayJSON) {
                if (configJSON instanceof JSONObject jsonObject) {
                    var siteConfig = SiteConfig.fromJson(jsonObject.toString());
                    siteConfigList.add(siteConfig);
                } else {
                    throw new IllegalArgumentException("Expected a JSON object for each site configuration.");
                }
            }

        } catch (JSONException e) {
            throw new RuntimeException("Failed to read IIS configuration", e);
        }

        return siteConfigList;
    }
}
