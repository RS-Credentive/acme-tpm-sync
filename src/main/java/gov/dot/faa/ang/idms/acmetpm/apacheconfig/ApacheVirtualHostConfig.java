package gov.dot.faa.ang.idms.acmetpm.apacheconfig;

public record ApacheVirtualHostConfig(
    String vHost,
    String sslCertificatePath,
    String sslPrivateKeyPath
) {}
