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

        String protocol = "UNKNOWN";
        if (destinationPort == 80) protocol = "HTTP";
        else if (destinationPort == 443) protocol = "HTTPS";
        else if (sourcePort == 80 || destinationPort == 80) protocol = "HTTP";
        else if (sourcePort == 443 || destinationPort == 443) protocol = "HTTPS";

        return String.format("TCP | %s:%d -> %s:%d | %s | %s | %dB | NORMAL",
                getSourceAddress().getHostAddress(), Math.abs(sourcePort),
                getDestinationAddress().getHostAddress(), Math.abs(destinationPort),
                flags, protocol, getLength());
    }
}