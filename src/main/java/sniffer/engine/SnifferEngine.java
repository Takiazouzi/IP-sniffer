package sniffer.engine;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import sniffer.parser.DefaultPacketParser;
import sniffer.utils.Logger;

import java.util.List;

/**
 * Core engine for the IP sniffer.
 * Handles packet capture, processing, and coordination of components.
 */
public class SnifferEngine {
    private PcapHandle handle;
    private String filterExpression;
    private boolean running = false;
    private int packetLimit; // 0 means unlimited
    private int totalPackets;
    private int totalBytes;
    private DefaultPacketParser parser;

    public SnifferEngine(String filterExpression, int packetLimit) {
        this.filterExpression = filterExpression;
        this.packetLimit = packetLimit;
        this.parser = new DefaultPacketParser();
    }

    /**
     * Starts the packet sniffing process.
     *
     * @throws Exception if initialization fails
     */
    public void start() throws Exception {
        Logger.info("Initializing packet sniffer...");

        // Find network interfaces
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        if (devices.isEmpty()) {
            throw new Exception("No network interfaces found");
        }

        // Log all available interfaces
        Logger.info("Available network interfaces:");
        for (int i = 0; i < devices.size(); i++) {
            PcapNetworkInterface dev = devices.get(i);
            Logger.info("  " + i + ": " + dev.getName() + " - " + dev.getDescription());
        }

        // Try to find a suitable network interface (prefer Wi-Fi or Ethernet, avoid Network Monitor)
        PcapNetworkInterface device = null;
        for (PcapNetworkInterface dev : devices) {
            String desc = dev.getDescription();
            if (desc != null && (desc.toLowerCase().contains("wifi") ||
                                desc.toLowerCase().contains("wireless") ||
                                desc.toLowerCase().contains("ethernet") ||
                                desc.toLowerCase().contains("realtek") ||
                                desc.toLowerCase().contains("intel"))) {
                device = dev;
                break;
            }
        }
        // If no preferred interface found, try to avoid Network Monitor
        if (device == null) {
            for (PcapNetworkInterface dev : devices) {
                String desc = dev.getDescription();
                if (desc != null && !desc.toLowerCase().contains("network monitor") &&
                    !desc.toLowerCase().contains("miniport")) {
                    device = dev;
                    break;
                }
            }
        }
        // Last resort - use first available
        if (device == null) {
            device = devices.get(0);
        }
        Logger.info("Using network interface: " + device.getName() + " (" + device.getDescription() + ")");

        // Open the device for live capture
        int snaplen = 65536; // Capture entire packets
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10; // milliseconds
        try {
            handle = device.openLive(snaplen, mode, timeout);
            Logger.info("Successfully opened network interface for packet capture");
        } catch (Exception e) {
            Logger.error("Failed to open network interface. Make sure you have administrator privileges and Npcap/WinPcap is installed.");
            throw new Exception("Cannot open network interface: " + e.getMessage(), e);
        }

        // Set filter to capture specified packets
        try {
            handle.setFilter(filterExpression, BpfProgram.BpfCompileMode.OPTIMIZE);
            Logger.info("Filter set to: " + filterExpression);
        } catch (Exception e) {
            Logger.info("Could not set filter, capturing all packets.");
        }

        running = true;
        Logger.info("Packet capture started.");

        capturePackets();
    }

    public void stop() {
        running = false;
        if (handle != null) {
            handle.close();
        }
        Logger.info("Captured " + totalPackets + " packets, " + totalBytes + " bytes.");
    }

    private void capturePackets() {
        long lastStatusTime = System.currentTimeMillis();
        int packetCheckCount = 0;
        try {
            while (running) {
                // Check if we've reached the packet limit
                if (packetLimit > 0 && stats.getTotalPackets() >= packetLimit) {
                    Logger.info("Packet limit of " + packetLimit + " reached!");
                    running = false;
                    break;
                }

                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    processPacket(packet);
                } else {
                    packetCheckCount++;
                    if (packetCheckCount % 50 == 0) {
                        Logger.info("Checked " + packetCheckCount + " times for packets, none received yet");
                    }
                }

                // Show status every 3 seconds
                long currentTime = System.currentTimeMillis();
                if (currentTime - lastStatusTime > 3000) {
                    if (packetLimit > 0) {
                        Logger.info("Sniffer active - " + stats.toString() + " (limit: " + packetLimit + ")");
                    } else {
                        Logger.info("Sniffer active - " + stats.toString());
                    }
                    lastStatusTime = currentTime;
                }
            }
        } catch (Exception e) {
            Logger.error("Error during packet capture: " + e.getMessage());
        } finally {
            stop();
        }
    }

    private void processPacket(Packet pcapPacket) {
        try {
            // Parse the packet
            sniffer.model.Packet parsedPacket = parser.parse(pcapPacket);
            if (parsedPacket == null) {
                return;
            }

            // Apply filter
            if (!filter.accept(parsedPacket)) {
                return;
            }

            // Record statistics
            stats.recordPacket(parsedPacket);

            // Analyze for security issues
            String analysisResult = analyzer.analyze(parsedPacket);
            if (analysisResult != null) {
                Logger.warn("Security alert: " + analysisResult);
            }

            // Log every packet
            Logger.info("[Packet #" + stats.getTotalPackets() + "] " + parsedPacket.toString());

        } catch (Exception e) {
            Logger.error("Error processing packet: " + e.getMessage());
        }
    }
}