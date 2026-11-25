package gov.dot.faa.ang.idms.acmetpm.webserver;

public sealed interface WebServerBridge permits ApacheWebServerBridge, IisWebServerBridge {

}
