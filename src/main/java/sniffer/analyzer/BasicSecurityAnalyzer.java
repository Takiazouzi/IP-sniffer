package sniffer.analyzer;

import sniffer.model.*;

/**
 * Basic security analyzer that checks for common security issues.
 */
public class BasicSecurityAnalyzer implements PacketAnalyzer {

    @Override
    public String analyze(Packet packet) {
        if (packet instanceof TcpPacket) {
            return analyzeTcpPacket((TcpPacket) packet);
        } else if (packet instanceof UdpPacket) {
            return analyzeUdpPacket((UdpPacket) packet);
        }
        return null; // No issues found
    }

    private String analyzeTcpPacket(TcpPacket packet) {
        StringBuilder issues = new StringBuilder();

        // Check for suspicious ports
        if (isSuspiciousPort(packet.getSourcePort()) || isSuspiciousPort(packet.getDestinationPort())) {
            issues.append("Suspicious port usage; ");
        }

        return issues.length() > 0 ? issues.toString() : null;
    }

    private String analyzeUdpPacket(UdpPacket packet) {
        StringBuilder issues = new StringBuilder();

        // Check for suspicious ports
        if (isSuspiciousPort(packet.getSourcePort()) || isSuspiciousPort(packet.getDestinationPort())) {
            issues.append("Suspicious port usage; ");
        }

        return issues.length() > 0 ? issues.toString() : null;
    }

    private boolean isSuspiciousPort(int port) {
        // Common suspicious ports (basic check) - exclude common ports like 443 (HTTPS)
        return port == 22 || port == 23 || port == 3389 || port == 5900;
    }
}