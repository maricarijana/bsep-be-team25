package com.example.bsep_team25.dto;

public class CAUserResponseDTO {

    private Long id;
    private String email;
    private String fullName;
    private String organization;
    private String temporaryPassword; // SAMO pri kreiranju, kasnije NULL
    private boolean mustChangePassword;
    private String role;
    private boolean active;

    // Constructor
    public CAUserResponseDTO(Long id, String email, String fullName, String organization,
                             String temporaryPassword, boolean mustChangePassword,
                             String role, boolean active) {
        this.id = id;
        this.email = email;
        this.fullName = fullName;
        this.organization = organization;
        this.temporaryPassword = temporaryPassword;
        this.mustChangePassword = mustChangePassword;
        this.role = role;
        this.active = active;
    }

    // Getters & Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getTemporaryPassword() { return temporaryPassword; }
    public void setTemporaryPassword(String temporaryPassword) {
        this.temporaryPassword = temporaryPassword;
    }

    public boolean isMustChangePassword() { return mustChangePassword; }
    public void setMustChangePassword(boolean mustChangePassword) {
        this.mustChangePassword = mustChangePassword;
    }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}
