# ECC Path
tpm2_createprimary -G ecc -c primary.ctx
tpm2_evictcontrol -c primary.ctx

tpm2_getcap handles-persistent # <- write down the handle (possibley 0x81000000)
tpm2_ptool init --primary-handle 0x81000000 # Replace with handle id if it is different
tpm2_ptool addtoken --pid=1 --sopin=mysopin --userpin=myuserpin --label=label
# tpm2_ptool addkey --algorithm=ecc256 --label="label" --key-label="ecc" --userpin=myuserpin
# tpm2_ptool addkey --algorithm=ecc256 --label="label" --userpin=myuserpin --attr-always-authenticate
# Next line is for a self-signed certificate
# openssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_ecc -out "cert.ecc" -config ossl.cnf 
# openssl req -new -subj '/CN=my key/' -sha256 -engine pkcs11 -keyform engine -key slot_1-label_ecc -out "cert.ecc" -config ossl.cnf 
# tpm2_ptool addcert --label=label --key-label=ecc "cert.ecc"

# keytool -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg /home/robert.ctr.sherwood/idms_tpm/pkcs11.cfg -list
