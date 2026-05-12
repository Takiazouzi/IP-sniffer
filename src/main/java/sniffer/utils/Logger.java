package sniffer.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Simple logging utility for the sniffer application.
 */
public class Logger {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public enum Level {
        INFO, WARN, ERROR
    }

    /**
     * Logs an info message.
     *
     * @param message the message to log
     */
    public static void info(String message) {
        log(Level.INFO, message);
    }

    /**
     * Logs a warning message.
     *
     * @param message the message to log
     */
    public static void warn(String message) {
        log(Level.WARN, message);
    }

    /**
     * Logs an error message.
     *
     * @param message the message to log
     */
    public static void error(String message) {
        log(Level.ERROR, message);
    }

    private static void log(Level level, String message) {
        String timestamp = LocalDateTime.now().format(formatter);
        System.out.println(String.format("[%s] %s: %s", timestamp, level, message));
    }
}