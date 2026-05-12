package sniffer.parser;

import sniffer.model.Packet;

/**
 * Interface for parsing raw packet data into structured Packet objects.
 */
public interface PacketParser {

    /**
     * Parses a Pcap4J packet into a Packet object.
     *
     * @param pcapPacket the Pcap4J packet to parse
     * @return the parsed Packet object, or null if parsing fails
     */
    Packet parse(org.pcap4j.packet.Packet pcapPacket);
}