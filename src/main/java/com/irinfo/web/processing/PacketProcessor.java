package com.irinfo.web.processing;

import com.irinfo.web.model.PacketRecord;
import com.irinfo.web.util.ConsoleTable;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;

/**
 * Drives per-packet processing: parse -> print -> accumulate.
 *
 * Currently an imperative loop target (see capture/* classes).
 * To convert to streams later:
 *   packets.stream()
 *          .map(p -> parser.parse(p, counter.incrementAndGet()))
 *          .peek(table::printRow)
 *          .collect(Collectors.toList());
 *
 * Note the DnsCache inside PacketParser is mutable shared state, so a
 * parallel stream would require synchronization or a different cache
 * strategy — fine for a sequential stream.
 */
public class PacketProcessor {

    private final PacketParser parser;
    private final ConsoleTable table = new ConsoleTable();
    private final List<PacketRecord> records = new ArrayList<>();

    public PacketProcessor(PacketParser parser) {
        this.parser = parser;
        table.printHeader();
    }

    public PacketRecord process(Packet packet, int count) {
        PacketRecord record = parser.parse(packet, count);
        table.printRow(record);
        records.add(record);
        return record;
    }

    public List<PacketRecord> getRecords() {
        return records;
    }
}