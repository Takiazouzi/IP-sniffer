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

        String srcIp = sourceAddress != null ? sourceAddress.getHostAddress() : "N/A";
        String dstIp = destinationAddress != null ? destinationAddress.getHostAddress() : "N/A";

        return String.format("IP | SRC: %-15s DST: %-15s PROTO: %-8s SIZE: %d bytes",
                srcIp, dstIp, protocolName, length);
    }
}