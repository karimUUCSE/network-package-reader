package com.irinfo.web.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.irinfo.web.model.PacketRecord;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;

/**
 * Writes the accumulated PacketRecords out as JSON and CSV.
 */
public class ReportExporter {

    public void export(File outputDir, String baseName, List<PacketRecord> records) {
        if (records.isEmpty()) {
            System.out.println("\nNo processed record payloads captured to construct text reports.");
            return;
        }

        System.out.println("\nGenerating structured network reports...");

        File jsonTarget = new File(outputDir, baseName + ".json");
        File csvTarget = new File(outputDir, baseName + ".csv");

        writeJson(jsonTarget, records);
        writeCsv(csvTarget, records);
    }

    private void writeJson(File target, List<PacketRecord> records) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(target, records);
            System.out.println("JSON schema successfully written to: " + target.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed compiling Jackson payload schema: " + e.getMessage());
        }
    }

    private void writeCsv(File target, List<PacketRecord> records) {
        try (PrintWriter writer = new PrintWriter(target)) {
            writer.println("index,protocol,source,destination,size,info,payload");
            for (PacketRecord record : records) {
                writer.printf("%d,\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\"%n",
                        record.index,
                        escapeCsv(record.protocol),
                        escapeCsv(record.source),
                        escapeCsv(record.destination),
                        record.size,
                        escapeCsv(record.info),
                        escapeCsv(record.payload));
            }
            System.out.println("CSV dataset successfully written to:   " + target.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed building tabular CSV log files: " + e.getMessage());
        }
    }

    private String escapeCsv(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\"", "\"\"");
    }
}