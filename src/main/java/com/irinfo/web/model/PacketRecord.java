package com.irinfo.web.model;

/**
 * Immutable-ish record of a single parsed packet.
 * Public fields preserved for Jackson's default field-visibility serialization.
 */
public class PacketRecord {

    public final int index;
    public final String protocol;
    public final String source;
    public final String destination;
    public final int size;
    public final String info;
    public final String payload;

    public PacketRecord(int index, String protocol, String source, String destination,
                        int size, String info, String payload) {
        this.index = index;
        this.protocol = protocol;
        this.source = source;
        this.destination = destination;
        this.size = size;
        this.info = info;
        this.payload = payload;
    }
}