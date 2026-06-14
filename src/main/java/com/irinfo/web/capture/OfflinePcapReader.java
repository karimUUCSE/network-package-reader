package com.irinfo.web.capture;

import com.irinfo.web.export.ReportExporter;
import com.irinfo.web.processing.PacketProcessor;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.File;

/**
 * Reads the first .pcap/.cap file found in the input directory.
 */
public class OfflinePcapReader {

    private final PacketProcessor processor;
    private final ReportExporter exporter;

    public OfflinePcapReader(PacketProcessor processor, ReportExporter exporter) {
        this.processor = processor;
        this.exporter = exporter;
    }

    public void run(File inputDir, File outputDir) throws Exception {

        File[] files = inputDir.listFiles((dir, name) ->
                name.endsWith(".pcap") || name.endsWith(".cap"));

        if (files == null || files.length == 0) {
            System.out.println();
            System.out.println("No PCAP files found in:");
            System.out.println(inputDir.getAbsolutePath());
            return;
        }

        File pcapFile = files[0];

        System.out.println();
        System.out.println("Reading:");
        System.out.println(pcapFile.getAbsolutePath());
        System.out.println();

        PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath());

        int count = 0;

        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                break;
            }

            count++;
            processor.process(packet, count);
        }

        handle.close();

        System.out.println();
        System.out.println("Finished reading raw file.");
        System.out.println("Packets Processed: " + count);

        String baseFileName = "parsed-" + System.currentTimeMillis();
        exporter.export(outputDir, baseFileName, processor.getRecords());
    }
}