package sniffer;

import sniffer.engine.SnifferEngine;
import sniffer.utils.Logger;

import java.io.File;
import java.util.Scanner;

/**
 * Main entry point for the IP Sniffer application.
 */
public class Main {
    public static void main(String[] args) {
        Logger.info("IP Sniffer starting...");

        Scanner scanner = new Scanner(System.in);
        String pcapFilePath = null;
        
        // Check if PCAP file path is provided as command line argument
        if (args.length > 0) {
            pcapFilePath = args[0];
            File file = new File(pcapFilePath);
            if (!file.exists()) {
                Logger.error("PCAP file not found: " + pcapFilePath);
                System.exit(1);
            }
        } else {
            // Ask user for PCAP file path
            System.out.println("\n=== IP Sniffer - PCAP File Analyzer ===");
            System.out.print("Enter the path to the PCAP file: ");
            pcapFilePath = scanner.nextLine().trim();
            
            File file = new File(pcapFilePath);
            if (!file.exists()) {
                Logger.error("PCAP file not found: " + pcapFilePath);
                scanner.close();
                System.exit(1);
            }
        }

        Logger.info("Loading PCAP file: " + pcapFilePath);

        // Ask user for packet filter type
        System.out.println("\nSelect packet type to analyze:");
        System.out.println("1. All IP packets");
        System.out.println("2. TCP packets only");
        System.out.println("3. UDP packets only");
        System.out.print("Enter your choice (1-3) [default: 1]: ");

        String filterExpression = "ip";
        String choice = scanner.nextLine().trim();
        if (choice.equals("2")) {
            filterExpression = "tcp";
        } else if (choice.equals("3")) {
            filterExpression = "udp";
        }

        Logger.info("Filter set to: " + filterExpression);

        SnifferEngine engine = new SnifferEngine(filterExpression, 0);

        try {
            // Process PCAP file
            Logger.info("\n" + "=".repeat(80));
            Logger.info("Processing PCAP file...");
            Logger.info("=".repeat(80));
            engine.processPcapFile(pcapFilePath);
            
            Logger.info("=".repeat(80));
            Logger.info("PCAP file processing completed!");
            Logger.info("=".repeat(80));

        } catch (Exception e) {
            Logger.error("Failed to process PCAP file: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
            engine.stop();
        }
    }
}