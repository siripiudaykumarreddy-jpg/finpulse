package com.uday.finpulse.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    // Fine for a portfolio project; in real systems this comes from an env variable.
    private final SecretKey key = Keys.hmacShaKeyFor(
            "this-is-a-32-byte-minimum-secret-key-for-hs256".getBytes());

    private final long expirationMs = 1000 * 60 * 60 * 10; // 10 hours

    public String generateToken(Long companyId, String email) {
        return Jwts.builder()
                .setSubject(email)
                .claim("companyId", companyId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody();
    }

    public Long extractCompanyId(String token) {
        return extractClaims(token).get("companyId", Long.class);
    }

    public boolean isValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
