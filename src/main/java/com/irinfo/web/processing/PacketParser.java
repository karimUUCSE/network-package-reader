package com.irinfo.web.processing;

import com.irinfo.web.model.PacketRecord;
import com.irinfo.web.util.PayloadUtil;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.net.InetAddress;

/**
 * Parses a single pcap4j {@link Packet} into a {@link PacketRecord}.
 *
 * Holds a reference to a shared {@link DnsCache} because ICMP/DNS
 * correlation requires state across packets (DNS queries populate the
 * cache, later ICMP packets read from it). Everything else is a pure
 * function of the input packet + index.
 */
public class PacketParser {

    private final DnsCache dnsCache;

    public PacketParser(DnsCache dnsCache) {
        this.dnsCache = dnsCache;
    }

    public PacketRecord parse(Packet packet, int index) {

        String protocol = "UNKNOWN";
        String source = "-";
        String destination = "-";
        String info = "";
        String payloadPreview = "";

        IpPacket ip = packet.get(IpPacket.class);

        if (ip != null) {
            InetAddress src = ip.getHeader().getSrcAddr();
            InetAddress dst = ip.getHeader().getDstAddr();

            source = src.getHostAddress();
            destination = dst.getHostAddress();

            DnsPacket dns = packet.get(DnsPacket.class);

            if (dns != null) {
                protocol = "DNS";
                info = parseDns(dns, destination);
            } else {
                TcpPacket tcp = packet.get(TcpPacket.class);
                UdpPacket udp = packet.get(UdpPacket.class);
                IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);

                if (tcp != null) {
                    protocol = "TCP";
                    info = portInfo(tcp.getHeader().getSrcPort().valueAsInt(),
                            tcp.getHeader().getDstPort().valueAsInt());
                    if (tcp.getPayload() != null) {
                        payloadPreview = PayloadUtil.extractPreview(tcp.getPayload().getRawData());
                    }

                } else if (udp != null) {
                    protocol = "UDP";
                    info = portInfo(udp.getHeader().getSrcPort().valueAsInt(),
                            udp.getHeader().getDstPort().valueAsInt());
                    if (udp.getPayload() != null) {
                        payloadPreview = PayloadUtil.extractPreview(udp.getPayload().getRawData());
                    }

                } else if (icmp != null) {
                    protocol = "ICMP";
                    info = parseIcmp(destination);

                } else {
                    IpNumber ipNumber = ip.getHeader().getProtocol();
                    protocol = ipNumber.toString();
                }
            }
        }

        return new PacketRecord(index, protocol, source, destination,
                packet.length(), info, payloadPreview);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private String parseDns(DnsPacket dns, String destination) {
        if (dns.getHeader().getQuestions().isEmpty()) {
            return "";
        }

        String domain = dns.getHeader().getQuestions().get(0).getQName().getName();

        if (dns.getHeader().isResponse()) {
            return "DNS Response: " + domain;
        } else {
            dnsCache.put(destination, domain);
            return "DNS Query: " + domain;
        }
    }

    private String parseIcmp(String destination) {
        if (dnsCache.contains(destination)) {
            return "Ping " + dnsCache.get(destination);
        }
        return "ICMP Packet";
    }

    private String portInfo(int srcPort, int dstPort) {
        return "Port " + srcPort + " -> " + dstPort;
    }
}