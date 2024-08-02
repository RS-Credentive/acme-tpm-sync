package gov.dot.faa.ang.idms.acmetpm;

public record DnsChallengeTracker(
    String resourceName,
    String digest,
    String status    
) {}
