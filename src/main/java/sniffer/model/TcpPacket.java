package sniffer.model;

/**
 * Simple TCP packet representation.
 */
public class TcpPacket extends IpPacket {
    private int sourcePort;
    private int destinationPort;
    private boolean synFlag;
    private boolean ackFlag;
    private boolean finFlag;

    public TcpPacket() {
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

    public boolean isSynFlag() {
        return synFlag;
    }

    public void setSynFlag(boolean synFlag) {
        this.synFlag = synFlag;
    }

    public boolean isAckFlag() {
        return ackFlag;
    }

    public void setAckFlag(boolean ackFlag) {
        this.ackFlag = ackFlag;
    }

    public boolean isFinFlag() {
        return finFlag;
    }

    public void setFinFlag(boolean finFlag) {
        this.finFlag = finFlag;
    }

    @Override
    public String toString() {
        String flags = "";
        if (synFlag) flags += "SYN,";
        if (ackFlag) flags += "ACK,";
        if (finFlag) flags += "FIN,";
        if (flags.endsWith(",")) flags = flags.substring(0, flags.length() - 1);
        if (flags.isEmpty()) flags = "NONE";

        String appProtocol = "TCP";
        if (getDestinationPort() == 80 || getSourcePort() == 80) appProtocol = "HTTP";
        else if (getDestinationPort() == 443 || getSourcePort() == 443) appProtocol = "HTTPS";
        else if (getDestinationPort() == 22 || getSourcePort() == 22) appProtocol = "SSH";
        else if (getDestinationPort() == 23 || getSourcePort() == 23) appProtocol = "TELNET";
        else if (getDestinationPort() == 21 || getSourcePort() == 21) appProtocol = "FTP";
        else if (getDestinationPort() == 25 || getSourcePort() == 25) appProtocol = "SMTP";

        String srcIp = getSourceAddress() != null ? getSourceAddress().getHostAddress() : "N/A";
        String dstIp = getDestinationAddress() != null ? getDestinationAddress().getHostAddress() : "N/A";

        return String.format("TCP | SRC: %-15s:%-5d DST: %-15s:%-5d FLAGS: %-12s APP: %-7s SIZE: %d bytes",
                srcIp, getSourcePort(),
                dstIp, getDestinationPort(),
                flags, appProtocol, getLength());
    }
}