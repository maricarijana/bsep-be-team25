package com.example.bsep_team25.iservice;

import com.example.bsep_team25.model.SessionInfo;

import java.util.List;

public interface ISessionManagementService {
     void saveSession(String email, SessionInfo session);
     List<SessionInfo> getActiveSessions(String email);
     void updateLastActivity(String email, String jti);
     void revokeSession(String email, String jti);
     void revokeAllExcept(String email, String currentJti);
    boolean isBlacklisted(String jti);
    void cleanupInactiveSessions(String email);

}
