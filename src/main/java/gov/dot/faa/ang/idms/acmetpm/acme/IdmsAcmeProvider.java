package gov.dot.faa.ang.idms.acmetpm.acme;

import org.shredzone.acme4j.provider.AbstractAcmeProvider;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;

import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.Session;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;

public class IdmsAcmeProvider extends AbstractAcmeProvider {
    PropLoader props;
    URL serverUrl;
    Session acmeSession;
    KeyPair userKeyPair;
    SSLContext tpmSslContext;
    public IdmsAcmeProvider(SSLContext sslContext) throws AcmeTpmException {
        super();
        tpmSslContext = sslContext;
    }

    @Override
    public boolean accepts(URI serverUri) {
        // TODO Auto-generated method stub

        // 10.23.4.193 10.27.33.94 10.22.65.8 10.22.65.4
        // var host = serverUri.getHost();

        // TODO: for now return True
        return true;
        
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
        return new EjbcaHttpConnector(settings, tpmSslContext);
    }

    
}
