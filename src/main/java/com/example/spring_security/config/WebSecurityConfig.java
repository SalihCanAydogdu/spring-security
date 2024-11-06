package com.example.spring_security.config;

import com.example.spring_security.jwt.AuthEntryPointJwt;
import com.example.spring_security.jwt.AuthTokenFilter;
import com.example.spring_security.jwt.JwtAuthenticationFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpMethod;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;
    
    @Autowired
    private AuthTokenFilter authTokenFilter;
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CORS ve CSRF ayarları
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            )
            .csrf(csrf -> csrf.disable())
            
            // Yetkilendirme ve yetkisiz erişim ayarları
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(unauthorizedHandler)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/signin").permitAll() // herkese açık erişim
                .requestMatchers("/api/auth/signup").permitAll() // herkese açık erişim
                .requestMatchers("/api/auth/logout").permitAll() // herkese açık erişim
                .requestMatchers("/api/auth/verify-code").permitAll() // herkese açık erişim
                .requestMatchers("/api/auth/resend-code").permitAll() // herkese açık erişim
                .requestMatchers("/api/auth/check-auth").permitAll() // herkese açık erişim
                .requestMatchers("/api/gizli-musteri/kaydet").permitAll() // Gizli müşteri kaydetme endpoint'ine herkese açık erişim 
                .requestMatchers("/api/gizliMusteriWord/downloadZip").permitAll() // herkese açık erişim
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // OPTIONS isteklerine izin ver
                .anyRequest().authenticated() // Diğer tüm istekler kimlik doğrulaması gerektirir
            );

        // Filtrelerin sıralaması
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:5173")); // Frontend adreslerinizi buraya ekleyin
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
