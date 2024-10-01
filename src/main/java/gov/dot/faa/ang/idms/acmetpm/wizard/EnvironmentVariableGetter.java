package gov.dot.faa.ang.idms.acmetpm.wizard;

import java.util.HashMap;

public class EnvironmentVariableGetter {
    private static HashMap<String, String> environmentVariableStrings = new HashMap<>();
    private static final String[] environmentVariablesArray = {
        "TSS2_LOG",
        "TPM2_PKCS11_STORE",
        "TPM2_PKCS11_TCTI"
    };

    public static HashMap<String, String> getVariables() {
        for (var envVar : environmentVariablesArray) {
            environmentVariableStrings.put(envVar, System.getenv(envVar));
        }
        return environmentVariableStrings;
    }

    
}
