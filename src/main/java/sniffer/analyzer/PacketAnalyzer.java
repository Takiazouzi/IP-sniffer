package sniffer.analyzer;

import sniffer.model.Packet;

/**
 * Interface for analyzing packets for security or other purposes.
 */
public interface PacketAnalyzer {

    /**
     * Analyzes a packet and returns analysis results.
     *
     * @param packet the packet to analyze
     * @return analysis result as a string, or null if no issues found
     */
    String analyze(Packet packet);
}