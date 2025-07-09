package com.msd.spring_boot_rest_api.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import com.msd.spring_boot_rest_api.model.Role;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final SecretKey JWT_SECRET = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private final long JWT_EXPIRATION_MS = 86400000; // 1 day

    // Generate token
    public String generateToken(String email, Role role) {
        System.out.println("Generating token for email: " + email + ", role: " + role);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION_MS);

        return Jwts.builder()
                .setSubject(email)
                .claim("role", role.name())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(JWT_SECRET, SignatureAlgorithm.HS512) // updated usage
                .compact();
    }

    // Get email from token
    public String getEmailFromJWT(String token) {
        Claims claims = Jwts
                .parserBuilder() // updated usage
                .setSigningKey(JWT_SECRET)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // Get role from token
    public Role getRoleFromJWT(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(JWT_SECRET)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String role = claims.get("role", String.class);
        return Role.valueOf(role);
    }

    // Validate token
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(JWT_SECRET)
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("JWT validation error: " + e.getMessage());
            return false;
        }
    }
}
