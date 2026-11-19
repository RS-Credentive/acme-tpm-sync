package gov.dot.faa.ang.idms.acmetpm.crypto.bridge;

public sealed interface TpmCryptoBridge  permits CapiTpmBridge, Pkcs11TpmBridge {

}
