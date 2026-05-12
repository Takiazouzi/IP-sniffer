package sniffer.stats;

import sniffer.model.IpPacket;
import sniffer.model.Packet;
import sniffer.model.TcpPacket;
import sniffer.model.UdpPacket;

/**
 * Collects and maintains traffic statistics.
 */
public class TrafficStats {
    private long totalPackets = 0;
    private long totalBytes = 0;
    private long ipPackets = 0;
    private long tcpPackets = 0;
    private long udpPackets = 0;

    /**
     * Records a packet in the statistics.
     *
     * @param packet the packet to record
     */
    public void recordPacket(Packet packet) {
        totalPackets++;
        totalBytes += packet.getLength();

        if (packet instanceof IpPacket) {
            ipPackets++;
            if (packet instanceof TcpPacket) {
                tcpPackets++;
            } else if (packet instanceof UdpPacket) {
                udpPackets++;
            }
        }
    }

    public long getTotalPackets() {
        return totalPackets;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public long getIpPackets() {
        return ipPackets;
    }

    public long getTcpPackets() {
        return tcpPackets;
    }

    public long getUdpPackets() {
        return udpPackets;
    }

    /**
     * Resets all statistics to zero.
     */
    public void reset() {
        totalPackets = 0;
        totalBytes = 0;
        ipPackets = 0;
        tcpPackets = 0;
        udpPackets = 0;
    }

    @Override
    public String toString() {
        return String.format("Traffic Stats - Total: %d packets (%d bytes), IP: %d, TCP: %d, UDP: %d",
                totalPackets, totalBytes, ipPackets, tcpPackets, udpPackets);
    }
}