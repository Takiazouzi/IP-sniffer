package sniffer;

import sniffer.engine.SnifferEngine;
import sniffer.utils.Logger;

import java.util.Scanner;

/**
 * Main entry point for the IP Sniffer application.
 */
public class Main {
    public static void main(String[] args) {
        Logger.info("IP Sniffer starting...");
        Logger.info("Note: This application requires administrator privileges to capture network packets.");
        Logger.info("Make sure you run this as Administrator and have Npcap installed.");

        // Ask user for packet filter type
        System.out.println("Select packet type to monitor:");
        System.out.println("1. All IP packets");
        System.out.println("2. TCP packets only");
        System.out.println("3. UDP packets only");
        System.out.print("Enter your choice (1-3): ");

        Scanner scanner = new Scanner(System.in);
        String filterExpression = "ip";
        String choice = scanner.nextLine().trim();
        if (choice.equals("2")) {
            filterExpression = "tcp";
        } else if (choice.equals("3")) {
            filterExpression = "udp";
        }

        System.out.println();
        System.out.println("How many packets would you like to capture?");
        System.out.println("1. Unlimited");
        System.out.println("2. 10 packets");
        System.out.println("3. 50 packets");
        System.out.println("4. 100 packets");
        System.out.println("5. Custom number");
        System.out.print("Enter your choice (1-5): ");

        int packetLimit = 0;
        String packetChoice = scanner.nextLine().trim();
        if (packetChoice.equals("2")) {
            packetLimit = 10;
        } else if (packetChoice.equals("3")) {
            packetLimit = 50;
        } else if (packetChoice.equals("4")) {
            packetLimit = 100;
        } else if (packetChoice.equals("5")) {
            System.out.print("Enter the number of packets to capture: ");
            try {
                packetLimit = Integer.parseInt(scanner.nextLine().trim());
                if (packetLimit < 0) {
                    packetLimit = 0;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid number, using unlimited");
                packetLimit = 0;
            }
        }

        if (packetLimit > 0) {
            Logger.info("Packet limit set to: " + packetLimit);
        } else {
            Logger.info("Capturing unlimited packets");
        }

        SnifferEngine engine = new SnifferEngine(filterExpression, packetLimit);

        // Add shutdown hook for clean exit
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Logger.info("Shutdown signal received...");
            engine.stop();
        }));

        try {
            // Start the sniffer
            engine.start();

            // Wait for user input to stop
            Logger.info("Press Enter to stop...");
            Logger.info("Tip: Open a web browser or make a network request to generate traffic for the sniffer to capture.");
            scanner.nextLine();

        } catch (Exception e) {
            Logger.error("Failed to start sniffer: " + e.getMessage());
            Logger.error("Common solutions:");
            Logger.error("1. Run as Administrator");
            Logger.error("2. Install Npcap: https://npcap.com/");
            Logger.error("3. Check that your network interface is active");
            e.printStackTrace();
        } finally {
            scanner.close();
            engine.stop();
        }
    }
}