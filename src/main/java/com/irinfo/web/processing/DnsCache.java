package com.irinfo.web.processing;

import java.util.HashMap;
import java.util.Map;

/**
 * Maps destination IPs to the domain name resolved via observed DNS queries.
 * Lets later ICMP packets be annotated with "Ping <hostname>".
 */
public class DnsCache {

    private final Map<String, String> cache = new HashMap<>();

    public void put(String ip, String domain) {
        cache.put(ip, domain);
    }

    public String get(String ip) {
        return cache.get(ip);
    }

    public boolean contains(String ip) {
        return cache.containsKey(ip);
    }
}