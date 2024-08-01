package gov.dot.faa.ang.idms.acmetpm.acme;

import java.net.http.HttpClient;
import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;

public class EjbcaHttpConnector extends HttpConnector {
    HttpClient.Builder clientBuilder = null;

    public EjbcaHttpConnector(NetworkSettings settings, SSLContext sslContext) {
        super(settings);
        clientBuilder = super.createClientBuilder();
        clientBuilder.sslContext(sslContext);
    }

    @Override
    public HttpClient.Builder createClientBuilder() {
        return clientBuilder;
    }
}
