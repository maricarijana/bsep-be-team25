package com.example.bsep_team25.dto;

import com.example.bsep_team25.model.Role;

public class UserDTO {
    private Long id;
    private String email;
    private String password;       // možeš ignorisati kod response-a
    private String confirmPassword; // koristi se samo prilikom registracije
    private String name;
    private String surname;
    private String organization;
    private Role role;
    private boolean active;

    public UserDTO() {}

    public UserDTO(Long id, String email, String password, String confirmPassword, String name, String surname,Role role, boolean active) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.confirmPassword = confirmPassword;
        this.name = name;
        this.surname = surname;
        this.role = role;
        this.active = active;

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}

