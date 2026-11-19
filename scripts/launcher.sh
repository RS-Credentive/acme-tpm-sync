#!/usr/bin/env bash
export TSS2_LOG=esys+NONE
export TPM2_PKCS11_STORE=/etc/acmetpm
export TPM2_PKCS11_TCTI="device:/dev/tpmrm0"
java -jar target/acmetpm-1.0-SNAPSHOT-jar-with-dependencies.jar $@
