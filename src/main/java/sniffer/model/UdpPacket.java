package sniffer.model;

/**
 * Simple UDP packet representation.
 */
public class UdpPacket extends IpPacket {
    private int sourcePort;
    private int destinationPort;

    public UdpPacket() {
        super();
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }

    @Override
    public String toString() {
        String protocol = "UDP";
        if (destinationPort == 53 || sourcePort == 53) protocol = "DNS";
        else if (destinationPort == 443 || sourcePort == 443) protocol = "QUIC";
        else if (destinationPort == 80 || sourcePort == 80) protocol = "HTTP";

        return String.format("UDP | %s:%d -> %s:%d | - | %s | %dB | NORMAL",
                getSourceAddress().getHostAddress(), Math.abs(sourcePort),
                getDestinationAddress().getHostAddress(), Math.abs(destinationPort),
                protocol, getLength());
    }
}