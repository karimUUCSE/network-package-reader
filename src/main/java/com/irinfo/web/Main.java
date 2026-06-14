package com.irinfo.web;

import com.irinfo.web.capture.LiveCapture;
import com.irinfo.web.capture.OfflinePcapReader;
import com.irinfo.web.export.ReportExporter;
import com.irinfo.web.processing.DnsCache;
import com.irinfo.web.processing.PacketParser;
import com.irinfo.web.processing.PacketProcessor;
import org.pcap4j.core.Pcaps;

import java.io.File;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("=================================================");
        System.out.println("Network Packet Reader");
        System.out.println("Pcap Version: " + Pcaps.libVersion());
        System.out.println("=================================================");

        File inputDir = new File("captures/input");
        File outputDir = new File("captures/output");

        if (!inputDir.exists()) inputDir.mkdirs();
        if (!outputDir.exists()) outputDir.mkdirs();

        Scanner scanner = new Scanner(System.in);

        System.out.println();
        System.out.println("1 - Live Capture");
        System.out.println("2 - Read PCAP File");
        System.out.print("Choose mode: ");

        String mode = scanner.nextLine().trim();

        // ── Wiring ───────────────────────────────────────────────────────
        DnsCache dnsCache = new DnsCache();
        PacketParser parser = new PacketParser(dnsCache);
        PacketProcessor processor = new PacketProcessor(parser);
        ReportExporter exporter = new ReportExporter();

        if ("2".equals(mode)) {
            new OfflinePcapReader(processor, exporter).run(inputDir, outputDir);
        } else {
            new LiveCapture(processor, exporter).run(outputDir);
        }
    }
}