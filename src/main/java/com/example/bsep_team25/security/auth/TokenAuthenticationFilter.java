package com.example.bsep_team25.security.auth;

import com.example.bsep_team25.service.SessionManagementService;
import com.example.bsep_team25.util.TokenUtils;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private TokenUtils tokenUtils;

    private UserDetailsService userDetailsService;
    private SessionManagementService sessionManagementService;

    protected final Log LOGGER = LogFactory.getLog(getClass());

    public TokenAuthenticationFilter(TokenUtils tokenHelper, UserDetailsService userDetailsService,SessionManagementService sessionManagementService) {
        this.tokenUtils = tokenHelper;
        this.userDetailsService = userDetailsService;
        this.sessionManagementService = sessionManagementService;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String username;

        // 1. Preuzimanje JWT tokena iz zahteva
        String authToken = tokenUtils.getToken(request);

        try {

            if (authToken != null) {


                String jti = tokenUtils.getJtiFromToken(authToken);
                if (jti != null && sessionManagementService.isBlacklisted(jti)) {
                    LOGGER.debug("Token is blacklisted!");

                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setHeader("X-Session-Revoked", "true");
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");

                    response.getWriter().write(
                            "{\"error\":\"SESSION_REVOKED\"," +
                                    "\"message\":\"Your session was terminated\"}"
                    );
                    return;
                }

                // 2. Citanje korisnickog imena iz tokena
                username = tokenUtils.getUsernameFromToken(authToken);

                if (username != null) {

                    // 3. Preuzimanje korisnika na osnovu username-a
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    // 4. Provera da li je prosledjeni token validan
                    if (tokenUtils.validateToken(authToken, userDetails)) {

                        if (jti != null) {
                            sessionManagementService.updateLastActivity(username, jti);
                        }

                        // 5. Kreiraj autentifikaciju
                        TokenBasedAuthentication authentication = new TokenBasedAuthentication(userDetails);
                        authentication.setToken(authToken);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }

        } catch (ExpiredJwtException ex) {
            LOGGER.debug("Token expired!");
        }

        // prosledi request dalje u sledeci filter
        chain.doFilter(request, response);
    }

}
