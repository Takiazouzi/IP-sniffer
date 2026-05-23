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
        String appProtocol = "UDP";
        if (getDestinationPort() == 53 || getSourcePort() == 53) appProtocol = "DNS";
        else if (getDestinationPort() == 67 || getSourcePort() == 67 || getDestinationPort() == 68 || getSourcePort() == 68) appProtocol = "DHCP";
        else if (getDestinationPort() == 69 || getSourcePort() == 69) appProtocol = "TFTP";
        else if (getDestinationPort() == 161 || getSourcePort() == 161) appProtocol = "SNMP";
        else if (getDestinationPort() == 123 || getSourcePort() == 123) appProtocol = "NTP";
        else if (getDestinationPort() == 443 || getSourcePort() == 443) appProtocol = "QUIC";

        String srcIp = getSourceAddress() != null ? getSourceAddress().getHostAddress() : "N/A";
        String dstIp = getDestinationAddress() != null ? getDestinationAddress().getHostAddress() : "N/A";

        return String.format("UDP | SRC: %-15s:%-5d DST: %-15s:%-5d APP: %-7s SIZE: %d bytes",
                srcIp, getSourcePort(),
                dstIp, getDestinationPort(),
                appProtocol, getLength());
    }
}