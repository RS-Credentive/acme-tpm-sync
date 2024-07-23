package gov.dot.faa.ang.idms.acmetpm.acme;

import java.net.http.HttpClient;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.AcmeTpm;



public class EjbcaHttpConnector extends HttpConnector {
    private static final AtomicReference<SSLContext> SSL_CONTEXT_REF = new AtomicReference<>();

    public EjbcaHttpConnector(NetworkSettings settings) {
        super(settings);
    }

    @Override
    public HttpClient.Builder createClientBuilder() {
        var builder = super.createClientBuilder();
        builder.sslContext(getTpmSslContext());
        return builder;
    }

    private SSLContext getTpmSslContext() {
        if (SSL_CONTEXT_REF == null) {
            try {
                var acmeTpm = new AcmeTpm();
                SSL_CONTEXT_REF.set(acmeTpm.getSSLContext());
            } catch (AcmeTpmException ex) {
                throw new RuntimeException("Error getting SSLContext from TpmProvider.");  
                // Not sure why, but we don't have to add throws RuntimeException to the method signature
            }
        } 
        
        return SSL_CONTEXT_REF.get();

    }


}
