package sniffer.model;

import java.net.InetAddress;

/**
 * Simple IP packet representation.
 */
public class IpPacket extends Packet {
    private InetAddress sourceAddress;
    private InetAddress destinationAddress;
    private int protocol;

    public IpPacket() {
        super();
    }

    public InetAddress getSourceAddress() {
        return sourceAddress;
    }

    public void setSourceAddress(InetAddress sourceAddress) {
        this.sourceAddress = sourceAddress;
    }

    public InetAddress getDestinationAddress() {
        return destinationAddress;
    }

    public void setDestinationAddress(InetAddress destinationAddress) {
        this.destinationAddress = destinationAddress;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    @Override
    public String toString() {
        String protocolName = "UNKNOWN";
        switch (protocol) {
            case 1: protocolName = "ICMP"; break;
            case 6: protocolName = "TCP"; break;
            case 17: protocolName = "UDP"; break;
            case 41: protocolName = "IPv6"; break;
            default: protocolName = "PROTOCOL_" + protocol; break;
        }

        return String.format("IP | %s -> %s | - | %s | %dB | NORMAL",
                sourceAddress.getHostAddress(), destinationAddress.getHostAddress(),
                protocolName, length);
    }
}