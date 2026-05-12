package sniffer.filter;

import sniffer.model.Packet;

/**
 * Interface for filtering packets based on criteria.
 */
public interface PacketFilter {

    /**
     * Determines if a packet should be accepted or filtered out.
     *
     * @param packet the packet to check
     * @return true if the packet should be accepted, false if filtered
     */
    boolean accept(Packet packet);
}