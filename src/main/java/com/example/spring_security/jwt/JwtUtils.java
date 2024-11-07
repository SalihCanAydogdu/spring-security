package com.example.spring_security.jwt;


import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.spring_security.security.services.UserDetailsImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

    @Value("${aydogdu.app.jwtSecret}")
    private String jwtSecret;

    @Value("${aydogdu.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    // Create JWT Token (With device information)
    public String generateJwtTokenWithDevice(Authentication authentication, String deviceInfo) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .claim("deviceInfo", deviceInfo) // We add device information
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationMs)))
                .signWith(getSigningKey())
                .compact();
    }

    // Getting device information from JWT
    public String getDeviceInfoFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("deviceInfo", String.class);
    }

    // Getting the username from the JWT
    public String getUserNameFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    // JWT validation and device information check
    public boolean validateJwtToken(String authToken, String currentDeviceInfo) {
        try {
            String tokenDeviceInfo = getDeviceInfoFromJwtToken(authToken);
            if (!tokenDeviceInfo.equals(currentDeviceInfo)) {
            	// If the device information does not match, the token is invalid.
                return false;
            }
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(authToken);
            return true;
        } catch (Exception e) {
        	// Error logging operations can be done here
            return false;
        }
    }
}
