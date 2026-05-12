package sniffer.filter;

import sniffer.model.IpPacket;
import sniffer.model.Packet;

/**
 * Default packet filter that accepts all IP packets.
 * Can be extended to implement more complex filtering logic.
 */
public class DefaultPacketFilter implements PacketFilter {

    @Override
    public boolean accept(Packet packet) {
        // Accept all IP packets by default
        return packet instanceof IpPacket;
    }
}