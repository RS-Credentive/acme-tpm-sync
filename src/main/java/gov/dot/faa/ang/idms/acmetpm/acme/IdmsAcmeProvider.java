package gov.dot.faa.ang.idms.acmetpm.acme;

import module java.base;

import org.shredzone.acme4j.provider.AbstractAcmeProvider;
import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.Session;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;

public class IdmsAcmeProvider extends AbstractAcmeProvider {
    PropLoader props;
    URL serverUrl;
    Session acmeSession;
    KeyPair userKeyPair;
    SSLContext tpmSslContext;
    public IdmsAcmeProvider(SSLContext sslContext) {
        super();
        tpmSslContext = sslContext;
    }

    @Override
    public boolean accepts(URI serverUri) {
        try {
            // Compare the hostname portion of the URI to the known whitelist of hosts.
            // TODO - this should probably be a property or something rather than being hard-coded.
            return Set.of(
                "idms-ra-dev.faa.gov",
                "idms-test.faa.gov",
                "acme.npe-idms.faa.gov"
            ).contains(serverUri.toURL().getHost());
        } catch (MalformedURLException _) {
            // If there is any problem processing the URL string, just return false.
            return false;
        }        
    }

    @Override
    public URL resolve(URI serverUri) {
        // This is EJBCA's ACME directory URL
        final String ACME_SCHEME = "https";
        final String ACME_PATH = Path.of("ejbca", "acme", "directory").toString();
        String serverHost = serverUri.getHost();
        try {
            return new URI(ACME_SCHEME, serverHost, ACME_PATH).toURL();
        } catch (URISyntaxException | MalformedURLException ex) {
            throw new AcmeProtocolException("Couldn't resolve " + serverUri.toString(), ex);
        }
    }

    @Override
    protected HttpConnector createHttpConnector(NetworkSettings settings) {
        return new EjbcaHttpConnector(settings, tpmSslContext);
    }

    
}
