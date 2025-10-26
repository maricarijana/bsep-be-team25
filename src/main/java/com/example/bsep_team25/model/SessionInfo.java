package com.example.bsep_team25.model;

import java.time.LocalDateTime;

public class SessionInfo {
    private String jti;              // UUID iz JWT-a (JTI)
    private String userEmail;            // Email korisnika
    private String clientIp;             // IP adresa
    private String browserInfo;          // "Chrome", "Firefox", "Safari"
    private String operatingSystem;      // "Windows", "macOS", "Linux"
    private String deviceCategory;       // "Desktop", "Mobile", "Tablet"
    private LocalDateTime loginTime;     // Kada je kreiran token
    private LocalDateTime lastAccessTime;// Poslednja aktivnost
    private boolean isActive;              // Da li je aktivan

    public SessionInfo(){
    }
    public SessionInfo(String jti, String userEmail, String clientIp, String userAgentHeader) {
        this.jti = jti;
        this.userEmail = userEmail;
        this.clientIp = clientIp;
        this.loginTime = LocalDateTime.now();
        this.lastAccessTime = LocalDateTime.now();
        this.isActive = true;

        // Automatski parsuj user agent
        this.parseUserAgentString(userAgentHeader);
    }
    private void parseUserAgentString(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            this.browserInfo = "Nepoznat pregledač";
            this.operatingSystem = "Nepoznat OS";
            this.deviceCategory = "Nepoznat uređaj";
            return;
        }

        // Detektuj browser
        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            this.browserInfo = "Chrome";
        } else if (userAgent.contains("Firefox")) {
            this.browserInfo = "Firefox";
        } else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) {
            this.browserInfo = "Safari";
        } else if (userAgent.contains("Edg")) {
            this.browserInfo = "Edge";
        } else if (userAgent.contains("Opera") || userAgent.contains("OPR")) {
            this.browserInfo = "Opera";
        } else {
            this.browserInfo = "Nepoznat pregledač";
        }

        // Detektuj OS
        if (userAgent.contains("Windows NT 10")) {
            this.operatingSystem = "Windows 10/11";
        } else if (userAgent.contains("Windows")) {
            this.operatingSystem = "Windows";
        } else if (userAgent.contains("Mac OS X")) {
            this.operatingSystem = "macOS";
        } else if (userAgent.contains("Linux")) {
            this.operatingSystem = "Linux";
        } else if (userAgent.contains("Android")) {
            this.operatingSystem = "Android";
        } else if (userAgent.contains("iPhone") || userAgent.contains("iPad")) {
            this.operatingSystem = "iOS";
        } else {
            this.operatingSystem = "Nepoznat OS";
        }

        if (userAgent.contains("Mobile")) {
            this.deviceCategory = "Mobilni";
        } else if (userAgent.contains("Tablet") || userAgent.contains("iPad")) {
            this.deviceCategory = "Tablet";
        } else {
            this.deviceCategory = "Desktop";
        }
    }

    public String getFullDeviceDescription() {
        return browserInfo + " na " + operatingSystem + " (" + deviceCategory + ")";
    }


    public String getJti() {
        return jti;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getBrowserInfo() {
        return browserInfo;
    }

    public String getOperatingSystem() {
        return operatingSystem;
    }

    public String getDeviceCategory() {
        return deviceCategory;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public LocalDateTime getLastAccessTime() {
        return lastAccessTime;
    }

    public boolean isActive() {
        return isActive;
    }

    // =================== SETTERI ===================

    public void setTokenId(String jti) {
        this.jti = jti;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public void setBrowserInfo(String browserInfo) {
        this.browserInfo = browserInfo;
    }

    public void setOperatingSystem(String operatingSystem) {
        this.operatingSystem = operatingSystem;
    }

    public void setDeviceCategory(String deviceCategory) {
        this.deviceCategory = deviceCategory;
    }

    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }

    public void setLastAccessTime(LocalDateTime lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }
}

