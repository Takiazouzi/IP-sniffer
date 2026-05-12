package sniffer.model;

import java.time.LocalDateTime;

/**
 * Simple base class for network packets.
 */
public abstract class Packet {
    protected LocalDateTime timestamp;
    protected int length;

    public Packet() {
        this.timestamp = LocalDateTime.now();
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    @Override
    public abstract String toString();
}