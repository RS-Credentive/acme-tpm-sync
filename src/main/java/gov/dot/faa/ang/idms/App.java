package gov.dot.faa.ang.idms;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;
import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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

    static PropLoader props;
    static TpmProvider tpmProvider;

    // Error codes for return functions.
    static final int FAIL = 1;
    static final int SUCCESS = 0;

    @Override
    public Integer call() throws Exception {
        if (printHelp) {
            printHelp();
            return SUCCESS;
        } else {
            return processCommand();
        }

    }

    private int processCommand() {
        switch (commandString) {
            case "help":
                return printHelp();

            case "list":
                return listDomains();

            case "info":
                if (domain == null) {
                    return printAllInfo();
                } else {
                    return printDomainInfo(domain);
                }

            case "getExpiring":
                return getExpiringDomains(expirationDate);
            
            case "addDomain":
                return addDomain(domain);
            

            default:
                System.out.println("The command " + commandString
                        + " is not recognized. Use command \"help\" for a list of commands.");
                return SUCCESS;
        }
    }

    // Command Functions

    private int printHelp() {
        // Note this function is called if the command "help" is entered, or if any
        // command is passed the "--help" switch, so figure it out and do the right
        // thing.
        System.out.println("Print a convenient help message here.");
        return SUCCESS;
    }

    private int listDomains() {
        try {
            var managedDomains = getManagedDomains();
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

    private int printAllInfo() {
        try {
            for (String domain : getManagedDomains()) {
                printDomainInfo(domain);
            }
        } catch (AcmeTpmException e) {
            System.out.println(
                    "Error receieved while trying to print information for all managed domains: " + e.getMessage());
            return FAIL;
        }
        return SUCCESS;
    }

    private int printDomainInfo(String domainString) {
        try {
            if (tpmProvider.isManagedDomain(domainString)) {
                System.out.println("Domain information for Domain: " + domainString);
                var keyInfo = tpmProvider.getKeyInfo(domainString);
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

    private int getExpiringDomains(Date expirationDate) {
        // if expiration date is not set, set it to the default configured in properties
        try {
            if (expirationDate == null) {
                PropLoader props = new PropLoader();
                int renewalLimit = Integer.valueOf(props.getProp("domains.renewalLimit"));
                expirationDate = Date.from(Instant.now().plus(Duration.ofDays(renewalLimit)));
            }
        } catch (NumberFormatException | AcmeTpmException e) {
            System.err.println("Error setting the renewal limit from properties: " + e.getMessage());
            return FAIL;
        }

        // Populate hashmap with {doma}
        var notAfterHashMap = new HashMap<String, Date>();
        try {
            var domains = tpmProvider.getDomains();
            if (domains.size() == 0) {
                System.out.println("No domains are managed on this server.");
                return SUCCESS;
            } else {
                for (var domain : tpmProvider.getDomains()) {
                    notAfterHashMap.put(domain, tpmProvider.domainCertExpiration(domain));
                }
            }
        } catch (AcmeTpmException e) {
            System.err.println("Error getting expiration dates from TPM backed token: " + e.getMessage());
            return FAIL;
        }

        // Iterate through the keys to see if the expiration date is earlier than the
        // requested date
        for (String domain : notAfterHashMap.keySet()) {
            if (notAfterHashMap.get(domain).after(expirationDate)) {
                System.out.println("Domain " + domain + " expiring on " + notAfterHashMap.get(domain));
            }
        }
        return SUCCESS;
    }

    private static int addDomain(String domain) {
        try {
            var tpmProvider = new TpmProvider(props.getProp("token.password"));
            tpmProvider.getDomainKeyPair(domain);
            System.out.println("Successfully added " + domain + " to managed domains.");
            return SUCCESS;
        } catch (Exception e) {
            System.err.println("Unable to add " + domain + " to managed Domains: " + e.getMessage());
            return FAIL;
        }
    }

    // Shared utility functions
    private static ArrayList<String> getManagedDomains() throws AcmeTpmException {
        TpmProvider tpmProvider = new TpmProvider(props.getProp("token.password"));
        return tpmProvider.getDomains();
    }

    

    public static void main(String[] args) {
        try {
            props = new PropLoader();
        } catch (AcmeTpmException e) {
            System.out.println("Could not load properties file: " + e.getMessage());
            System.exit(1);
        }
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

}
