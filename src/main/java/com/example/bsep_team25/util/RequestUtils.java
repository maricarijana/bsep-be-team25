package com.example.bsep_team25.util;

import jakarta.servlet.http.HttpServletRequest;

public class RequestUtils {

    /**
     * Izvuci realnu IP adresu klijenta
     */
    public static String extractClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("X-Real-IP");
        }

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        // Ako ima više IP adresa (proxy chain), uzmi prvu
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress != null ? ipAddress : "Nepoznata IP";
    }

    /**
     * Izvuci User-Agent header
     */
    public static String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Nepoznat klijent";
    }
}