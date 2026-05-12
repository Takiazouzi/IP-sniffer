package sniffer.parser;

import org.pcap4j.packet.*;

/**
 * Simple packet parser that creates basic packet objects.
 */
public class DefaultPacketParser implements PacketParser {

    @Override
    public sniffer.model.Packet parse(org.pcap4j.packet.Packet pcapPacket) {
        try {
            // Check if it's an IP packet
            IpV4Packet ipPacket = pcapPacket.get(IpV4Packet.class);
            if (ipPacket != null) {
                return parseIpPacket(ipPacket);
            }

            // Unknown packet
            sniffer.model.Packet packet = new sniffer.model.Packet() {
                @Override
                public String toString() {
                    return "Unknown Packet: " + getLength() + " bytes";
                }
            };
            packet.setLength(pcapPacket.length());
            return packet;

        } catch (Exception e) {
            sniffer.model.Packet packet = new sniffer.model.Packet() {
                @Override
                public String toString() {
                    return "Parse Error: " + e.getMessage();
                }
            };
            packet.setLength(pcapPacket.length());
            return packet;
        }
    }

    private sniffer.model.Packet parseIpPacket(IpV4Packet ipPacket) {
        IpV4Packet.IpV4Header header = ipPacket.getHeader();

        // Check protocol
        if (header.getProtocol().value() == 6) { // TCP
            sniffer.model.TcpPacket tcpPacket = new sniffer.model.TcpPacket();
            setIpFields(tcpPacket, header);
            setTcpFields(tcpPacket, ipPacket);
            return tcpPacket;
        } else if (header.getProtocol().value() == 17) { // UDP
            sniffer.model.UdpPacket udpPacket = new sniffer.model.UdpPacket();
            setIpFields(udpPacket, header);
            setUdpFields(udpPacket, ipPacket);
            return udpPacket;
        } else {
            // Other IP packet
            sniffer.model.IpPacket ip = new sniffer.model.IpPacket();
            setIpFields(ip, header);
            return ip;
        }
    }

    private void setIpFields(sniffer.model.IpPacket packet, IpV4Packet.IpV4Header header) {
        packet.setSourceAddress(header.getSrcAddr());
        packet.setDestinationAddress(header.getDstAddr());
        packet.setProtocol(header.getProtocol().value());
        packet.setLength(header.getTotalLength());
    }

    private void setTcpFields(sniffer.model.TcpPacket tcpPacket, IpV4Packet ipPacket) {
        org.pcap4j.packet.TcpPacket tcp = ipPacket.get(org.pcap4j.packet.TcpPacket.class);
        if (tcp != null) {
            org.pcap4j.packet.TcpPacket.TcpHeader tcpHeader = tcp.getHeader();
            tcpPacket.setSourcePort(tcpHeader.getSrcPort().valueAsInt());
            tcpPacket.setDestinationPort(tcpHeader.getDstPort().valueAsInt());
            tcpPacket.setSynFlag(tcpHeader.getSyn());
            tcpPacket.setAckFlag(tcpHeader.getAck());
            tcpPacket.setFinFlag(tcpHeader.getFin());
        }
    }

    private void setUdpFields(sniffer.model.UdpPacket udpPacket, IpV4Packet ipPacket) {
        org.pcap4j.packet.UdpPacket udp = ipPacket.get(org.pcap4j.packet.UdpPacket.class);
        if (udp != null) {
            org.pcap4j.packet.UdpPacket.UdpHeader udpHeader = udp.getHeader();
            udpPacket.setSourcePort(udpHeader.getSrcPort().valueAsInt());
            udpPacket.setDestinationPort(udpHeader.getDstPort().valueAsInt());
            udpPacket.setLength(udpHeader.getLength());
        }
    }
}