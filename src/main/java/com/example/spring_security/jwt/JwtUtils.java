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

    // JWT Token oluşturma (Cihaz bilgisi ile)
    public String generateJwtTokenWithDevice(Authentication authentication, String deviceInfo) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .claim("deviceInfo", deviceInfo) // Cihaz bilgisini ekliyoruz
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationMs)))
                .signWith(getSigningKey())
                .compact();
    }

    // JWT içinden cihaz bilgisini alma
    public String getDeviceInfoFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("deviceInfo", String.class);
    }

    // JWT içinden kullanıcı adını alma
    public String getUserNameFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    // JWT doğrulama ve cihaz bilgisi kontrolü
    public boolean validateJwtToken(String authToken, String currentDeviceInfo) {
        try {
            String tokenDeviceInfo = getDeviceInfoFromJwtToken(authToken);
            if (!tokenDeviceInfo.equals(currentDeviceInfo)) {
                // Cihaz bilgisi uyuşmuyorsa token geçersiz
                return false;
            }
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(authToken);
            return true;
        } catch (Exception e) {
            // Hata loglama işlemleri burada yapılabilir
            return false;
        }
    }
}
