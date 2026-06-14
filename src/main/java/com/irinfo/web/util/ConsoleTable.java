package com.irinfo.web.util;

import com.irinfo.web.model.PacketRecord;

/**
 * Handles the fixed-width console table output.
 */
public class ConsoleTable {

    private static final String DIVIDER =
            "------------------------------------------------------------------------------------------------------------------------";

    private static final String ROW_FORMAT =
            "%-8s %-10s %-18s %-18s %-10s %-40s %-15s%n";

    public void printHeader() {
        System.out.println(DIVIDER);
        System.out.printf(ROW_FORMAT,
                "PACKET", "PROTO", "SOURCE", "DESTINATION", "SIZE", "INFO", "PAYLOAD");
        System.out.println(DIVIDER);
    }

    public void printRow(PacketRecord record) {
        System.out.printf(ROW_FORMAT,
                record.index,
                record.protocol,
                record.source,
                record.destination,
                record.size,
                record.info,
                record.payload);
    }
}