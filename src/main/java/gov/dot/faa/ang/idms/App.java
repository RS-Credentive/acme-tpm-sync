package gov.dot.faa.ang.idms;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpm;
import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.io.Console;
import java.util.Scanner;

import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
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

    @Option(names = { "-i", "--input" }, paramLabel = "Input", description = "Input for an object that requires input.")
    private String input = null;

    @Option(names = {"-o", "--order"}, paramLabel = "OrderID", description = "Order Identifier")
    private String orderID = null;

    @Option(names = { "--debug" }, paramLabel = "Debug", description = "Show debug logs.")
    private boolean debug = false;

    static AcmeTpm acmeTpm;

    private static Logger logger;    

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
            // Log the time 
            Properties loggingProperties = System.getProperties();
            loggingProperties.put("org.slf4j.simpleLogger.showDateTime", true);
            loggingProperties.put("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS");
            System.setProperties(loggingProperties);

            // Check for --debug flag
            if (debug) {
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
                logger = LoggerFactory.getLogger(App.class);
                logger.debug("DEBUG logging enabled.");
            } else {
                logger = LoggerFactory.getLogger(App.class);
                logger.info("No --debug flag detected. Logging level set to INFO.");
            }
            // Log now since we just set the debug level.
            
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
        // We can give print the help message without setting anything up
        if (commandString.equals("help")) {
            return printHelp();
        }

        // Everything else requires a TPM
        logger.debug("Initializing AcmeTPM class object.");
        try {
            acmeTpm = new AcmeTpm();
        } catch (AcmeTpmException e) {
            System.err.println("Could not initialize acmeTpm: " + e.getMessage());
            System.exit(1);
        }

        // Check for "requestusercert" first, in case the userkey doesn't exist
        if (commandString.equals("requestusercert")) {
            return requestUserCert();
        }

        // This command requires the userkey to be present
        try {
            if (acmeTpm.userKeyExists()) {
                acmeTpm.initialize();
            } else {
                System.err.println(
                        "The user key does not exist on the TPM. Please call 'requestusercert' before using any other commands.");
                return FAIL;
            }
        } catch (AcmeTpmException e) {
            System.err.println("Error checking for user key: " + e.getMessage());
            return FAIL;
        }

        // From here on, we can use the rest of the commands.
        switch (commandString) {
            case "installusercert":
                return installUserCert();

            case "diagnostic":
                return diagnostic();

            case "listdomains":
                return listDomains();

            case "printdomaininfo":
                if (domain == null) {
                    return printAllInfo();
                } else {
                    return printDomainInfo(domain);
                }

            case "listexpiringdomains":
                return getExpiringDomains(expirationDate);

            case "adddomain":
                return addDomain(domain);

            case "checkorders":
                return checkOrders();

            case "deletedomain":
                return deleteDomain(domain);

            case "updatedomain":
                // return r(domain);

            case "revokecertificate":
                if (domain != null) {
                    return revokeCertificate(domain);
                } else if (orderID != null) {
                    return revokeCertificate(orderID);
                }
                

            default:
                System.out.println("The command " + commandString
                        + " is not recognized. Use command \"help\" for a list of commands.");
                return SUCCESS;
        }
    }

    /**
     * Functions implementing command options
     */

    /**
     * Prints diagnostic information about the TPM and keystore
     * 
     * @return
     */
    private int diagnostic() {
        try {
            // List user info
            System.out.println("User information:");
            var keyInfo = acmeTpm.getUserKeyInfo();
            if (keyInfo.size() > 0) {
                for (var key : keyInfo.keySet()) {
                    System.out.println(key + " : " + keyInfo.get(key));
                }
            } else {
                System.out.println("No attributes registered for keyStore entry");
            }

            // List domains
            System.out.println("\nManaged Domain Information:");
            listDomains();

            // List ACME metadata
            System.out.println("\nFetching ACME server metadata to confirm connectivity.");
            var metadataValues = acmeTpm.testAcmeConnection();
            for (String key : metadataValues.keySet()) {
                System.out.println("KEY: " + key + " / VALUE: " + metadataValues.get(key));
            }

            // Apache Virtual Hosts
            System.out.println("\nListing Apache Virtual Hosts configured.");
            var vhostConfigs = acmeTpm.listApacheVirtualHosts();

            for (String vhost : vhostConfigs.keySet()) {
                System.out.println("Virtual Host: " + vhost);
                for (var entry : vhostConfigs.get(vhost).entrySet()) {
                    System.out.println("\t" + entry.getKey() + ": " + entry.getValue());
                }
            }

            // Pending orders
            System.out.println("Listing orders associated with the account on the acme server.");
            for (var orderStatusString: acmeTpm.getOrderInfo()) {
                System.out.println(orderStatusString);
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
            return SUCCESS;
        } catch (AcmeTpmException e) {
            System.err.println("Unable to generate user private key and CSR: " + e.getMessage());
            ;
            return FAIL;
        }
    }

    /**
     * Prompts the user to paste a CERT in PEM format and updates the user
     * keystore with the new cert.
     * 
     * @return SUCCESS(0) or FAIL(1)
     */
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
     * managed.
     * 
     * @return SUCCESS(0) if we were able to get a list, or FAIL(0) if we weren't
     *         able to get a list
     */
    private int listDomains() {
        try {
            var managedDomains = acmeTpm.listDomains();
            if (managedDomains.isEmpty()) {
                System.out.println("No domains are being managed on this server.");
            } else {
                System.out.println("We are managing keys and certificates for the following domains:\n");
                for (String domain : managedDomains) {
                    System.out.println(domain);
                }
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error receieved while trying to list Domains: " + e.getMessage());
            return FAIL;
        }

        return SUCCESS;
    }

    /**
     * Print information for all domains under management. Calls getManagedDomains
     * and then calls printDomainInfo for each domain
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
     * Prints information about the keypairs and certificates for one of the domains
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
     * request a certificate for the domain from the ACME server
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
            return SUCCESS;
        } catch (Exception e) {
            System.err.println("Unable to add " + domain + " to managed Domains: " + e.getMessage());
            return FAIL;
        }
    }

    /**
     * Login to check the status of orders and respond appropriately. A status is
     * returned for each function.
     * 
     * @return
     */
    private static int checkOrders() {
        try {
            System.out.println("Logging in and checking status of ACME Requests");
            var orderStatus = acmeTpm.checkOrders();
            if (orderStatus.keySet().size() < 1) {
                System.out.println("There are no ACME Requests in progress.");
            }
            for (var key : orderStatus.keySet()) {
                System.out.println("ACME REQUEST: " + key);
                for (var statusLine : orderStatus.get(key)) {
                    System.out.println(statusLine);
                }
            }

        } catch (AcmeTpmException e) {
            System.err.println("Error checking orders: " + e.getMessage());
            return FAIL;
        }
        return SUCCESS;

    }

    /**
     * Deletes a domain from the list of managed domains. This does not
     * automatically revoke the certificate for the domain
     * 
     * @param domain
     * @return
     */
    private int deleteDomain(String domain) {
        try {
            acmeTpm.deleteDomain(domain);
            return SUCCESS;
        } catch (AcmeTpmException e) {
            System.out.println("Unable to delete domain " + domain + ": " + e.getMessage());
            return FAIL;
        }
    }

    /**
     * 
     * @param domainOrOrder an identifier for a certificate that is either a domain, or an order ID for a valid order 
     * (if the certificate is no longer available)
     * @return
     */
    private int revokeCertificate(String domainOrOrder) {
        // TODO: fix this
        return SUCCESS;
    }

    /**
     * main
     * 
     * @param args
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

}
