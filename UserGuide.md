# Introduction

AcmeTPM is a java based command line utility which supports management of web server TLS private keys and certificates, leveraging a TPM for private key protection.

# Usage overview

AcmeTPM has two primary modes of operation:

1. It can be called interactively from the command line to perform essential functions, such as adding a new managed domain, or listing the certificates that will expire before a certain date.
1. It can be run periodically as a scheduled job to automatically renew any certificates that it manages, and are about to expire.

# Configuration

AcmeTPM may not work if it is not properly configured. This section describes the configuration. 

AcmeTPM's behavior is controlled by a properties file. The property file is stored in "/etc/acmetpm/acmetpm.properties" and contains the properties listed below.

## ejbca.adresses
The addresses of the EJBCA servers providing ACME services. By default, the list is "INSERT LIST OF ADDRESSES" (dns record?)

## token.label
The Label associated with the virtual token containing keys. The default is "acmetpm"

## token.password

The password used to authenticate to the virtual token. There is no default value. The password will be randomly generated when the token is created.

## token.libraryPath

The library path of the pkcs11 library. By default this is "/usr/lib64/pkcs11/libtpm2_pkcs11.so".

## domains.renewalLimit

When auto-renewing certificates, AcmeTPM will automatically renew a certificate if it expires in less than the number of days specified by this property. By default this is 90 days.

# Interactive Use

AcmeTpm must be called with a command, and optional flags. This section identifies the commands and their purpose, and describes the optional flags.

All commands accept an optional "--help" flag which will provide more details about the command.

## acmetpm help

This command lists provides usage information about the command. It is equivalent to "acmetpm --help"

## acmetpm userinit

This command creates the user key pair if it does not exist, and outputs a certificate signing request. By default it reuses an existing private key.

*Example: acmetpm userinit*

The optional '--rekey' or '-r' flag generates a new key pair, replacing the existing keys.

*Example: acmetpm userinit --rekey*

## acmetpm list

This command lists all domains managed by acmetpm

## acmetpm info

This comman provides information about keys and certificates associated with domains managed by acmetpm.

*Example: acmetpm info*

The optional '--domain'  or "-d" flag may be provided in order to provide information about a single domain

*Example: acmetpm info --domain www.example.com*

*Example: acmetpm info -d www.example.com*

## acmetpm listexpiring

This command lists all domains under management that expire before a given date. If no date is provided, it calculates the date from the current date plus the number of days set in [domains.renewallimit](#domainsrenewallimit). By default this is [current date] + 90 days.

*Example: acmetpm listexpiring* 

The "--expiration" or "-e" flag may be provided to change the calculated expiration date. This flag accepts a date formatted in ISO 8601 format (YYYY-MM-DD)

*Example: acmetpm listexpiring 2025-09-30* 

This will list all certificates expiring before September 30, 2025.

## acmetpm add

This command adds a new managed domain to the managed domain list.

The "--domain" or "-d" flag must be provided.

*Example: acmetpm add --domain www.example.com*

*Example: acmetpm add -d www.example.com*

Note that this command does not automatically request a certificate from the ACME server. This must be done with the [*acmetpm request*](#acmetpm-request) command

## acmetpm delete

This command deletes an existing managed domain from the managed domain list.

The "--domain" or "-d" flag must be provided.

*Example: acmetpm delete --domain www.example.com*

*Example: acmetpm delete -d www.example.com*

Note that this command does not automatically revoke the certificate associated with the domain. If revocation is required, it may be done out of band or via the [*acmetpm revoke*](#acmetpm-revoke) command.

## acmetpm request

This command attempts to request certificates for managed domains. It will automatically request certificates for any expiring domains.

*mExaple: acmetpm request*

The "--domain" or "-d" flag may be provided to limit the requests to a single domain, and must be provided for a domain added with the [*acmetpm add*](#acmetpm-add) command.

*Example: acmetpm request --domain www.example.com*

*Example: acmetpm request -d www.example.com*

NOTE: As discussed in [*acmetpm add*](#acmetpm-add), this command must be run after a domain is added. The --domain or -d flag must be provided, since acmetpm request will not renew the self-signed certificate that is generated when a new managed domain is added. 

## acmetpm revoke

This command will attempt to revoke a certificate associated with a managed domain. 

The "--domain" or "-d" flag must be provided.

*Example: acmetpm revoke --domain www.example.com*

*Example: acmetpm revoke -d www.example.com*

# Scripted Use

Acmetpm may be run non-interactively to automatically renew all managed certificates that are about to expire.

The command to run is [*acmetpm request*](#acmetpm-request), which will automatically identify all managed domains with a certificate issued from an ACME server that will expire within the number of days specified in [*domains.renewalLimit*](#domainsrenewallimit) and request and updated certificate.