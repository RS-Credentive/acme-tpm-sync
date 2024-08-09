package gov.dot.faa.ang.idms.acmetpm;

import java.io.Serializable;
import java.util.ArrayList;

import org.shredzone.acme4j.Order;


public record DomainTracker(
    String alias,
    String vHostID,
    ArrayList<String> domains,
    Order order
) implements Serializable {}
