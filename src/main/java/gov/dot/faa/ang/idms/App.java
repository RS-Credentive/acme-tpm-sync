package gov.dot.faa.ang.idms;

import gov.dot.faa.ang.idms.acmetpm.AcmeTpmException;
import gov.dot.faa.ang.idms.acmetpm.PropLoader;
import gov.dot.faa.ang.idms.acmetpm.tpmcrypto.TpmProvider;

import java.util.ArrayList;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "acmetpm", mixinStandardHelpOptions = true, version = "acmetpm 0.1",
         description = "Enables management of TPM backed SSL Server keys with ACME")
class App implements Callable<Integer> {
    @Parameters(index="0", paramLabel = "<command>", defaultValue = "help", description = "The subcommand to execute (type \"help\" for a list of commands)")
    String commandString = "help";

    @Option(names = {"-h", "--help"}, paramLabel = "Help", description = "Prints information about the command.")
    private boolean printHelp = false;

    @Option(names = {"-d", "--domain"}, paramLabel = "Domain", description = "A domain for the command to operate on.")
    private String domain = null;

    static PropLoader props;
    static TpmProvider tpmProvider;

    @Override
    public Integer call() throws Exception {
        if (printHelp) {
            printHelp();
            return 0;
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

        
            default:
                System.out.println("The command " + commandString + " is not recognized. Use command \"help\" for a list of commands."
                );
                return 0;
        }
    }

    private int printHelp() {
        // Note this function is called if the command "help" is entered, or if any command is passed the "--help" switch, so figure it out and do the right thing.
        System.out.println("Print a convenient help message here.");
        return 0;
    }

    private int listDomains() {
        System.out.println("We are managing keys and certificates for the following domains:");
        try {
            for (String domain : getManagedDomains()) {
                System.out.println(domain);
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error receieved while trying to list Domains: " + e.getMessage());
            return 1;
        }

        return 0;
    }

    private int printAllInfo() {
        try {
            for (String domain : getManagedDomains()) {
                printDomainInfo(domain);
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error receieved while trying to print information for all managed domains: " + e.getMessage());
            return 1;
        }
        return 0;
    }

    private int printDomainInfo(String domainString) {
        try {
            if (tpmProvider.isManagedDomain(domainString)) {
                System.out.println("Domain information for Domain: " + domainString);
                var keyInfo = tpmProvider.getKeyInfo(domainString);
                return 0;
            } else {
                System.out.println(domainString + " is not a managed domain.");
                return 1;
            }
        } catch (AcmeTpmException e) {
            System.out.println("Error while attempting to get info for domain " + domainString + ": " + e.getMessage());
            return 1;
        }
    }


    public static void main(String[] args) {
        try {
            props = new PropLoader();
        } catch (AcmeTpmException e) {
            System.out.println("Could not load properties file: " + e.getMessage()); 
            System.exit(1);
        }

        try {
            tpmProvider = new TpmProvider(props.getTokenPassword());
        } catch (AcmeTpmException e) {
            System.out.println("Unable to initialize TPM: " + e.getMessage());
        }
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

    private static ArrayList<String> getManagedDomains() throws AcmeTpmException {
        return tpmProvider.getDomains();
    }


}
