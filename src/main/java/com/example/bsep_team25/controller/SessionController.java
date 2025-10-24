package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.SessionInfoDTO;
import com.example.bsep_team25.model.SessionInfo;
import com.example.bsep_team25.service.SessionManagementService;
import com.example.bsep_team25.util.TokenUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth/sessions")
public class SessionController {

    @Autowired
    private SessionManagementService sessionManagementService;

    @Autowired
    private TokenUtils tokenUtils;

    /**
     * GET /api/auth/sessions
     * Vrati sve aktivne sesije trenutnog korisnika
     */
    @GetMapping
    public ResponseEntity<List<SessionInfoDTO>> getActiveSessions(
            Authentication authentication,
            HttpServletRequest request) {

        String email = authentication.getName();

        // Očisti neaktivne sesije pre prikazivanja
        sessionManagementService.cleanupInactiveSessions(email);

        // Preuzmi trenutni JTI
        String currentToken = tokenUtils.getToken(request);
        String currentJti = tokenUtils.getJtiFromToken(currentToken);

        // Preuzmi sve aktivne sesije
        List<SessionInfo> sessions = sessionManagementService.getActiveSessions(email);

        // Konvertuj u DTO
        List<SessionInfoDTO> sessionDTOs = sessions.stream()
                .map(session -> {
                    SessionInfoDTO dto = new SessionInfoDTO();
                    dto.setJti(session.getJti());
                    dto.setDeviceDescription(session.getFullDeviceDescription());
                    dto.setIpAddress(session.getClientIp());
                    dto.setCreatedAt(session.getLoginTime());
                    dto.setLastUsed(session.getLastAccessTime());
                    dto.setCurrentSession(session.getJti().equals(currentJti));
                    return dto;
                })
                .collect(Collectors.toList());

        return ResponseEntity.ok(sessionDTOs);
    }

    /**
     * POST /api/auth/sessions/revoke
     * Opozovi jednu sesiju
     */
    @PostMapping("/revoke")
    public ResponseEntity<?> revokeSession(
            @RequestBody Map<String, String> payload,
            Authentication authentication) {

        String jtiToRevoke = payload.get("jti");
        String email = authentication.getName();

        if (jtiToRevoke == null || jtiToRevoke.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "JTI is required"));
        }

        sessionManagementService.revokeSession(email, jtiToRevoke);

        return ResponseEntity.ok(Map.of("message", "Session revoked successfully"));
    }

    /**
     * POST /api/auth/sessions/revoke-all
     * Opozovi sve sesije osim trenutne
     */
    @PostMapping("/revoke-all")
    public ResponseEntity<?> revokeAllOtherSessions(
            Authentication authentication,
            HttpServletRequest request) {

        String email = authentication.getName();

        // Preuzmi trenutni JTI
        String currentToken = tokenUtils.getToken(request);
        String currentJti = tokenUtils.getJtiFromToken(currentToken);

        if (currentJti == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid token"));
        }

        sessionManagementService.revokeAllExcept(email, currentJti);

        return ResponseEntity.ok(Map.of("message", "All other sessions revoked successfully"));
    }
}