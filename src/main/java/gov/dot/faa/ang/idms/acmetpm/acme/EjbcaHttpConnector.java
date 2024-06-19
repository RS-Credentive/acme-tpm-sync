package gov.dot.faa.ang.idms.acmetpm.acme;

import java.net.http.HttpClient;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Objects;

import javax.net.ssl.SSLContext;

import org.shredzone.acme4j.connector.HttpConnector;
import org.shredzone.acme4j.connector.NetworkSettings;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

public class EjbcaHttpConnector extends HttpConnector {
    private static final AtomicReference<SSLContext> SSL_CONTEXT_REF = new AtomicReference<>();

    public EjbcaHttpConnector(NetworkSettings settings) {
        super(settings);
    }

    @Override
    public HttpClient.Builder createClientBuilder() {
        var builder = super.createClientBuilder();
        // builder.sslContext(getTpmSslContext());
        return builder;
    }

    // private SSLContext getTpmSslContext() {
        // if (SSL_CONTEXT_REF == null) {
        //     try {
        //         TpmProvider provider = new TpmProvider();
        //         SSL_CONTEXT_REF.set(provider.getSSLContext());
        //     } catch (AcmeTpmException ex) {
        //         throw new RuntimeException("Error getting SSLContext from TpmProvider.");  
        //         // Not sure why, but we don't have to add throws RuntimeException to the method signature
        //     }
        // } 
        
        // return Objects.requireNonNull(SSL_CONTEXT_REF.get());

    // }


}
