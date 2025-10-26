package com.example.bsep_team25.dto;

import java.time.LocalDateTime;

public class SessionInfoDTO {
    private String jti;
    private String deviceDescription;     // "Chrome na Windows (Desktop)"
    private String ipAddress;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsed;
    private boolean currentSession;         // Da li je ovo trenutni token

    public SessionInfoDTO() {}

    // =================== GETTERI ===================

    public String getJti() {
        return jti;
    }

    public String getDeviceDescription() {
        return deviceDescription;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getLastUsed() {
        return lastUsed;
    }

    public boolean isCurrentSession() {
        return currentSession;
    }

    // =================== SETTERI ===================

    public void setJti(String jti) {
        this.jti = jti;
    }

    public void setDeviceDescription(String deviceDescription) {
        this.deviceDescription = deviceDescription;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setLastUsed(LocalDateTime lastUsed) {
        this.lastUsed = lastUsed;
    }

    public void setCurrentSession(boolean currentSession) {
        this.currentSession = currentSession;
    }
}
