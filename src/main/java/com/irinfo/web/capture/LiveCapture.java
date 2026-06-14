package com.irinfo.web.capture;

import com.irinfo.web.export.ReportExporter;
import com.irinfo.web.processing.PacketProcessor;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.File;

/**
 * Live packet capture from the first non-loopback interface.
 */
public class LiveCapture {

    private final PacketProcessor processor;
    private final ReportExporter exporter;

    private volatile boolean running = true;

    public LiveCapture(PacketProcessor processor, ReportExporter exporter) {
        this.processor = processor;
        this.exporter = exporter;
    }

    public void run(File outputDir) throws Exception {

        PcapNetworkInterface nif = findActiveInterface();

        if (nif == null) {
            System.out.println("No active network interface found.");
            return;
        }

        System.out.println();
        System.out.println("Using Interface: " + nif.getName());

        PcapHandle handle = nif.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                50);

        String baseFileName = "capture-" + System.currentTimeMillis();
        String outputFile = new File(outputDir, baseFileName + ".pcap").getAbsolutePath();

        PcapDumper dumper = handle.dumpOpen(outputFile);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running = false;

            try {
                dumper.close();
                handle.close();
            } catch (Exception ignored) {
            }

            System.out.println();
            System.out.println("Raw PCAP binary saved to:");
            System.out.println(outputFile);

            exporter.export(outputDir, baseFileName, processor.getRecords());
        }));

        System.out.println();
        System.out.println("Waiting for packets... (Press Ctrl+C to terminate and save structural logs)");
        System.out.println();

        int count = 0;

        while (running) {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                continue;
            }

            count++;
            dumper.dump(packet, handle.getTimestamp());
            processor.process(packet, count);
        }
    }

    private PcapNetworkInterface findActiveInterface() throws Exception {
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            if (!dev.isLoopBack() && !dev.getAddresses().isEmpty()) {
                return dev;
            }
        }
        return null;
    }
}