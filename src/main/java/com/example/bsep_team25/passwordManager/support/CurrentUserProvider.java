package com.example.bsep_team25.passwordManager.support;

import com.example.bsep_team25.model.User;
import com.example.bsep_team25.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CurrentUserProvider {

    private final UserService userService;

    public User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getPrincipal() == null) {
            throw new AccessDeniedException("No authentication present");
        }

        Object principal = auth.getPrincipal();

        // Tvoj User implementira UserDetails -> često će principal već biti User
        if (principal instanceof User u) {
            return u;
        }
        if (principal instanceof UserDetails ud) {
            String email = ud.getUsername(); // kod tebe je username = email
            User user = userService.findByEmail(email);
            if (user == null) throw new AccessDeniedException("Authenticated user not found: " + email);
            return user;
        }

        throw new AccessDeniedException("Unsupported principal type: " + principal.getClass());
    }
}
