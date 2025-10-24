package com.example.bsep_team25.service;

import com.example.bsep_team25.iservice.ISessionManagementService;
import com.example.bsep_team25.model.SessionInfo;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class SessionManagementService implements ISessionManagementService {

    // In-memory storage
    private final Map<String, List<SessionInfo>> userSessions = new ConcurrentHashMap<>();
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public void saveSession(String email, SessionInfo session) {
        userSessions.computeIfAbsent(email, k -> new ArrayList<>()).add(session);
    }

    public List<SessionInfo> getActiveSessions(String email) {
        List<SessionInfo> sessions = userSessions.get(email);
        if (sessions == null) return new ArrayList<>();

        return sessions.stream()
                .filter(s -> !blacklistedTokens.contains(s.getJti()) && s.isActive())
                .collect(Collectors.toList());
    }

    public void updateLastActivity(String email, String jti) {
        List<SessionInfo> sessions = userSessions.get(email);
        if (sessions != null) {
            sessions.stream()
                    .filter(s -> s.getJti().equals(jti))
                    .findFirst()
                    .ifPresent(s -> s.setLastAccessTime(LocalDateTime.now()));
        }
    }

    public void revokeSession(String email, String jti) {
        blacklistedTokens.add(jti);
        List<SessionInfo> sessions = userSessions.get(email);
        if (sessions != null) {
            sessions.stream()
                    .filter(s -> s.getJti().equals(jti))
                    .findFirst()
                    .ifPresent(s -> s.setActive(false));
        }
    }

    public void revokeAllExcept(String email, String currentJti) {
        List<SessionInfo> sessions = userSessions.get(email);
        if (sessions != null) {
            sessions.forEach(s -> {
                if (!s.getJti().equals(currentJti)) {
                    blacklistedTokens.add(s.getJti());
                    s.setActive(false);
                }
            });
        }
    }

    public boolean isBlacklisted(String jti) {
        return blacklistedTokens.contains(jti);
    }
    public void cleanupInactiveSessions(String email) {
        List<SessionInfo> sessions = userSessions.get(email);
        if (sessions != null) {
            sessions.removeIf(session -> !session.isActive());

            // Ako nema više sesija, ukloni ceo entry iz mape
            if (sessions.isEmpty()) {
                userSessions.remove(email);
            }
        }
    }
}