package gov.dot.faa.ang.idms;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpm;
import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;
import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;

import java.io.Console;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;

import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "acmetpm", mixinStandardHelpOptions = true, version = "acmetpm 0.1", description = "Enables management of TPM backed SSL Server keys with ACME")
class App implements Callable<Integer> {
    @Parameters(index = "0", paramLabel = "<command>", defaultValue = "help", description = "The subcommand to execute (type \"help\" for a list of commands)")
    String commandString = "help";

    @Option(names = { "-h", "--help" }, paramLabel = "Help", description = "Prints information about the command.")
    private boolean printHelp = false;

    @Option(names = { "-d",
            "--domain" }, paramLabel = "Domain", description = "A domain for the command to operate on.")
    private String domain = null;

    @Option(names = { "-e",
            "--expiration" }, paramLabel = "Expiration", description = "A cutoff date to compare to the expiration date in the certificates.")
    private Date expirationDate = null;

    @Option(names = {"-i", "--input"}, paramLabel = "Input", description = "Input for an object that requires input.")

    static PropLoader props;
    static AcmeTpm acmeTpm;

    // Error codes for return functions.
    static final int FAIL = 1;
    static final int SUCCESS = 0;

    /**
     * Function called by main to run the command. Checks to see if "--help" or "-h"
     * was called and return help message,
     * otherwise calls processCommand() to do something
     * 
     * @return
     */
    @Override
    public Integer call() throws Exception {
        if (printHelp) {
            return printHelp();
        } else {
            return processCommand();
        }

    }

    /**
     * process the commands directives passed in on the command line, and dispatch
     * to the appropriate method
     * 
     * @return SUCCESS(0) or FAIL(0) as returned by the underlying method
     */
    private int processCommand() {
        switch (commandString) {
            case "help":
                return printHelp();

            case "requestusercert":
                return requestUserCert();

            case "installusercert":
                return installUserCert();

            case "diagnostic":
                return Diagnostic();

            case "list":
                return listDomains();

            case "info":
                if (domain == null) {
                    return printAllInfo();
                } else {
                    return printDomainInfo(domain);
                }

            case "listexpiring":
                return getExpiringDomains(expirationDate);

            case "add":
                return addDomain(domain);

            case "delete":
                return deleteDomain(domain);

            case "request":
                return requestCertificate(domain);

            case "revoke":
                return revokeCertificate(domain);

            default:
                System.out.println("The command " + commandString
                        + " is not recognized. Use command \"help\" for a list of commands.");
                return SUCCESS;
        }
    }

    // Functions implementing command options

    private int Diagnostic() {
        try {
            // List user info
            System.out.println("User information:");
            System.out.println("User keystore entry exists.");
            var keyInfo = acmeTpm.getUserKeyInfo();
            if (keyInfo.size() > 0) {
                for (var key : keyInfo.keySet()) {
                    System.out.println(key + " : " + keyInfo.get(key));
                }
            } else { 
                System.out.println("No attributes registered for keyStore entry");
            }

            // List domains
            System.out.println("Managed Domain Information:");
            listDomains();
            
            // List ACME metadata
            var metadataValues = acmeTpm.testAcmeConnection();
            for (String key: metadataValues.keySet()) {
                System.out.println("KEY: " + key + " / VALUE: " + metadataValues.get(key));
            }


            return SUCCESS;
        } catch (AcmeTpmException e) {
            System.err.println("Diagnostic failed: " + e.getMessage());
            return FAIL;
        }
    }

    /**
     * Prints a help message to the screen
     * 
     * @return SUCCESS(0)
     */
    private int printHelp() {
        // Note this function is called if the command "help" is entered, or if any
        // command is passed the "--help" switch, so figure it out and do the right
        // thing.
        System.out.println("Print a convenient help message here.");
        return SUCCESS;
    }

    /**
     * Generates and displays a Certifiate Signing Request for the user account
     * 
     * @return SUCCESS(0) or FAIL(1)
     */
    private int requestUserCert() {
        try {
            String csr = acmeTpm.generateUserCSR();
            System.out.println(csr);
        } catch (AcmeTpmException e) {
            System.err.println("Unable to generate user private key and CSR: " + e.getMessage());;
            return FAIL;
        }
        return SUCCESS;
    }

    private int installUserCert() {
        try {
            Console console = System.console();
            if (console == null) {
                System.err.println("Unable to get system console.");
                return FAIL;
            }

            Scanner certScanner = new Scanner(System.in);
            StringBuilder pemCertBuilder = new StringBuilder();
            String input;
            boolean recording = false;

            System.out.println("Paste the certificate in PEM format:");
            
            while ((certScanner.hasNextLine())) {
                input = certScanner.nextLine();
                // Ignore everthing up until "BEGIN CERTIFICATE"
                if (input.contains("BEGIN CERTIFICATE")) {
                    recording = true;
                }
                // Stop when we see "END CERTIFICATE"
                if (input.contains("END CERTIFICATE")) {
                    pemCertBuilder.append(input);
                    break;
                }

                // Add the PEM contents to the StringBuilder
                if (recording) {
                    pemCertBuilder.append(input + "\n");
                }
            }
            certScanner.close();

            // grab the certstring from the stringbuilder
            var pemCert = pemCertBuilder.toString();

            // send the PEM cert to the update function.
            acmeTpm.updateUserCert(pemCert);
        } catch (AcmeTpmException e) {
            System.err.println("Unable to install user Certificate: " + e.getMessage());
            return FAIL;
        }

        return SUCCESS;
    }

    /**
     * Print a list of managed domains, or a message indicating that no domains are
     * registered.
     * 
     * @return SUCCESS(0) if we were able to get a list, or FAIL(0) if we weren't
     *         able to get a list
     */
    private int listDomains() {
        try {
            var managedDomains = acmeTpm.listDomains();
            if (managedDomains.size() > 0) {
                System.out.println("We are managing keys and certificates for the following domains:\n");
                for (String domain : managedDomains) {
                    System.out.println(domain);
                }
            } else {
                System.out.println("No domains are being managed on this server.");
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error receieved while trying to list Domains: " + e.getMessage());
            return FAIL;
        }

        return SUCCESS;
    }

    /**
     * Print information for all domains under management. Calls getManagedDomains
     * and then calls printDomainInfo for
     * each domain
     * 
     * @return SUCCESS(0) if able to print info or FAIL(1) if an exception is raised
     *         while trying.
     */
    private int printAllInfo() {
        try {
            var domains = acmeTpm.listDomains();
            if (domains.size() == 0) {
                System.out.println("No domains are under management by the TPM.");
            } else {
                for (String domain : domains) {
                    printDomainInfo(domain);
                }
            }
        } catch (AcmeTpmException e) {
            System.out.println(
                    "Error receieved while trying to print information for all managed domains: " + e.getMessage());
            return FAIL;
        }
        return SUCCESS;
    }

    /**
     * Prints information about the keypairs and certificats for one of the domains
     * under management
     * 
     * @param domainString - a string representing a domain, usually a hostname
     * @return SUCCESS(0) if able to print info or FAIL(1) if an exception is raised
     *         while trying.
     */
    private int printDomainInfo(String domainString) {
        try {
            var domainInfo = acmeTpm.getDomainInfo(domainString);
            if (domainInfo.size() > 0) {
                System.out.println("Domain information for Domain: " + domainString);
                var keyInfo = acmeTpm.getKeyInfo(domainString);
                for (var key : keyInfo.keySet()) {
                    System.out.println(key + " : " + keyInfo.get(key));
                }
                return SUCCESS;
            } else {
                System.out.println(domainString + " is not a managed domain.");
                return FAIL;
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error while attempting to get info for domain " + domainString + ": " + e.getMessage());
            return FAIL;
        }
    }

    /**
     * print a list of domains that will expire before the date provided
     * 
     * @param expirationDate - the expiration date to compare the domain
     *                       certificates against
     * @return SUCCESS(0) if able to print expiring domains or FAIL(1) if an
     *         exception is raised while trying.
     */
    private int getExpiringDomains(Date expirationDate) {
        HashMap<String, Date> expiringDomains;

        // Populate hashmap with "domain" : certificate expiration date
        try {
            expiringDomains = acmeTpm.getExpiringDomains(expirationDate);
        } catch (AcmeTpmException e) {
            System.err.println("Error getting expiration dates from TPM backed token: " + e.getMessage());
            return FAIL;
        }

        // Iterate through the keys to see if the expiration date is earlier than the
        // requested date
        if (expiringDomains.size() > 0) {
            for (String domain : expiringDomains.keySet()) {
                System.out.println("Domain " + domain + " expiring on " + expiringDomains.get(domain));
            }
        } else {
            System.out.println("No domain certificate expire before" + expirationDate.toString());
        }
        return SUCCESS;
    }

    /**
     * Add a domain to the list of managed domains. This does not automatically
     * request a certificate for the domain
     * 
     * @param domain - domain identifier to add (usually hostname)
     * @return SUCCESS(0) if able to add domain or FAIL(1) if an exception is raised
     *         while trying.
     */
    private static int addDomain(String domain) {
        try {
            System.out.print("Generating and storing keypair for  " + domain + "...");
            acmeTpm.addDomain(domain);
            System.out.println("done.");
            
            System.out.print("Generating CSR for " + domain + "...");
            var certReq = acmeTpm.generateCSR(domain);
            System.out.println("done.");

            System.out.print("Submitting request to ACME server ...");        
            
            System.out.println("done.");
            return SUCCESS;
        } catch (Exception e) {
            System.err.println("Unable to add " + domain + " to managed Domains: " + e.getMessage());
            return FAIL;
        }
    }

    /**
     * Deletes a domain from the list of managed domains. This does not
     * automatically revoke the certificate for the domain
     * 
     * @param domain
     * @return
     */
    private int deleteDomain(String domain) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deleteDomain'");
    }

    private int revokeCertificate(String domain) {
        // TODO: fix this
        return SUCCESS;
    }
    // Shared utility functions-

    /**
     * main
     * 
     * @param args
     */
    public static void main(String[] args) {
        try {
            props = new PropLoader();
        } catch (AcmeTpmException e) {
            System.out.println("Could not load properties file: " + e.getMessage());
            System.exit(1);
        }

        try {
            acmeTpm = new AcmeTpm();
        } catch (AcmeTpmException e) {
            System.err.println("Could not initialize acmeTpm: " + e.getMessage());
            System.exit(1);
        }

        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

}
