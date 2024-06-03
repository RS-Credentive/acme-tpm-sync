package gov.dot.faa.ang.idms.acmetpm.acme;

import org.shredzone.acme4j.provider.AbstractAcmeProvider;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.exception.AcmeProtocolException;

public class IdmsAcmeProvider extends AbstractAcmeProvider {
    public IdmsAcmeProvider() {
        super();
    }

    @Override
    public boolean accepts(URI serverUri) {
        // TODO Auto-generated method stub

        // 10.23.4.193 10.27.33.94 10.22.65.8 10.22.65.4
        var host = serverUri.getHost();
        throw new UnsupportedOperationException("Unimplemented method 'accepts'");
    }

    @Override
    public URL resolve(URI serverUri) {
        // This is EJBCA's ACME directory URL
        final String DIRECTORY_URL = "/ejbca/acme/directory";
        String serverUriString = serverUri.toString();
        try {
            return new URL(serverUriString + DIRECTORY_URL);
        } catch (MalformedURLException ex) {
            throw new AcmeProtocolException(serverUriString, ex);
        }
    }

    @Override
    protected HttpConnector createHttpConnector(NetworkSettings settings) {
        return new EjbcaConnector(settings);
    }
    
}
