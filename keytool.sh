 #!/usr/bin/env bash
export TPM2_PKCS11_STORE=/etc/acmetpm
export TPM2_PKCS11_TCTI="device:/dev/tpmrm0"
keytool -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg /etc/acmetpm/acmetpm.conf $@
