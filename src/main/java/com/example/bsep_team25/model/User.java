package com.example.bsep_team25.model;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
public class User implements UserDetails, Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password; // čuva se hash (BCrypt)

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String surname;

    @Column(nullable = false)
    private String organization;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role; // ADMIN, CA_USER, USER

    @Column(nullable = false)
    private boolean isActive = false;

    public User() {}

    public User(Long id, String email, String password, String name, String surname,
                String organization, Role role, boolean isActive) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.name = name;
        this.surname = surname;
        this.organization = organization;
        this.role = role;
        this.isActive = isActive;
    }

    // Getteri i setteri
    public String getSurname() { return surname; }
    public void setSurName(String surName) { this.surname = surName; }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    @Override
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public boolean isActive() { return isActive; }
    public void setActive(boolean active) { isActive = active; }

    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }

    // ===================== UserDetails implementacija =====================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        // Ako želiš da korisnik loginuje preko email-a
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // možeš kasnije dodati logiku ako nalog ističe
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // možeš dodati logiku za ban korisnika
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // možeš dodati logiku ako lozinka ističe
    }

    @Override
    public boolean isEnabled() {
        return this.isActive;
    }

    // ======================================================================

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", name='" + name + '\'' +
                ", surname='" + surname + '\'' +
                ", organization='" + organization + '\'' +
                ", role=" + role +
                ", isActive=" + isActive +
                '}';
    }
}
