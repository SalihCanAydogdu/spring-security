package com.example.spring_security.controllers;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.spring_security.models.ERole;
import com.example.spring_security.models.Role;
import com.example.spring_security.models.User;
import com.example.spring_security.payload.responses.MessageResponse;
import com.example.spring_security.security.repository.UserRepository;
import com.example.spring_security.security.services.TokenBlackListService;
import com.example.spring_security.security.services.UserDetailsImpl;
import com.example.spring_security.security.services.UserDetailsServiceImpl;

import com.example.spring_security.payload.requests.SignupRequest;
import com.example.spring_security.payload.requests.SigninRequest;
import com.example.spring_security.payload.requests.VerifyCodeRequest;
import com.example.spring_security.payload.requests.ResendCodeRequest;
import com.example.spring_security.security.repository.RoleRepository;
import com.example.spring_security.security.services.EmailService;
import com.example.spring_security.security.services.VerificationService;
import com.example.spring_security.jwt.JwtUtils;


import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    private final TokenBlackListService tokenBlackListService;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final RoleRepository roleRepository;

    @Autowired
    private UserDetailsServiceImpl userDetailsService; // Kullanıcıyı username ile doğrulamak için

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    // Kullanıcı başına bucket'ları tutacak bir harita
    private final Map<String, Bucket> bucketCache = new ConcurrentHashMap<>();

    @Autowired
    public AuthController(TokenBlackListService tokenBlackListService, RoleRepository roleRepository, VerificationService verificationService,
                          EmailService emailService) {
        this.tokenBlackListService = tokenBlackListService;
        this.roleRepository = roleRepository;
        this.verificationService = verificationService;
        this.emailService = emailService;
    }

    // Her kullanıcı için rate limit belirleyen bir metot
    private Bucket resolveBucket(String username) {
        return bucketCache.computeIfAbsent(username, key -> createNewBucket());
    }

    private Bucket createNewBucket() {
        Refill refill = Refill.intervally(5, Duration.ofMinutes(10)); // 10 dakikada 5 istek
        Bandwidth limit = Bandwidth.classic(5, refill); // Bandwidth limiti belirler
        return Bucket.builder().addLimit(limit).build(); // Yeni bir bucket oluşturur
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        // Set default role as ROLE_USER
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue(value = "jwt", required = false) String token, HttpServletResponse response) {
        if (token == null || token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("JWT cookie is missing or already logged out");
        }

        // Token'ı kara listeye ekleyelim
        tokenBlackListService.add(token);

        // Çerezi temizle (Max-Age=0 ile çerezi sil)
        String cookie;
        String env = System.getenv("SPRING_PROFILES_ACTIVE"); // Ortam değişkenini kontrol et
        if ("prod".equals(env)) {
            // Üretim ortamı için Secure ve SameSite=None
            cookie = "jwt=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0";
        } else {
            // Geliştirme ortamı için Secure=false ve SameSite=Lax
            cookie = "jwt=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
        }

        response.setHeader("Set-Cookie", cookie);

        return ResponseEntity.ok("Logout successful!");
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SigninRequest signinRequest, @RequestHeader("User-Agent") String userAgent) {
        // Rate Limiting kontrolü
        Bucket bucket = resolveBucket(signinRequest.getUsername());
        if (bucket.tryConsume(1)) { // 1 hak tüketmeye çalış
            try {
                // Kullanıcıyı authenticate et
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(signinRequest.getUsername(), signinRequest.getPassword())
                );

                // Güvenlik bağlamına authentication ekle
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Kullanıcı detaylarını al
                UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

                // Doğrulama kodu oluştur ve e-posta ile gönder
                String verificationCode = emailService.sendVerificationCode(userDetails.getEmail());
                if (verificationCode == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new MessageResponse("Error: Verification code could not be sent."));
                }

                // Doğrulama kodunu sakla
                verificationService.storeVerificationCode(userDetails.getUsername(), verificationCode);

                // Başarılı yanıt döndür
                return ResponseEntity.ok(new MessageResponse("Signin successful and verification code sent to email."));

            } catch (Exception e) {
                // Hata durumunda uygun yanıt döndür
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("Error: Invalid username or password."));
            }
        } else {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(new MessageResponse("Error: Too many login attempts. Please try again later."));
        }
    }

    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody VerifyCodeRequest verifyCodeRequest, @RequestHeader("User-Agent") String userAgent, HttpServletResponse response) {
        String username = verificationService.getUsernameFromCode(verifyCodeRequest.getCode());

        if (username == null) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid or expired verification code!"));
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // JWT token oluştur (cihaz bilgisi ile)
        String jwt = jwtUtils.generateJwtTokenWithDevice(authentication, userAgent);

        // Çerez ayarları
        String env = System.getenv("SPRING_PROFILES_ACTIVE"); // Ortam değişkeni ile ortamı kontrol edin
        String cookie;
        if ("prod".equals(env)) {
            // Üretim ortamı için
            cookie = String.format("jwt=%s; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=%d", jwt, 4 * 60 * 60);
        } else {
            // Geliştirme ortamı için
            cookie = String.format("jwt=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d", jwt, 4 * 60 * 60);
        }

        response.setHeader("Set-Cookie", cookie);

        return ResponseEntity.ok(new MessageResponse("Verification successful and JWT stored in cookie."));
    }

    @PostMapping("/resend-code")
    public ResponseEntity<?> resendVerificationCode(@RequestBody ResendCodeRequest resendCodeRequest) {
        // Rate Limiting kontrolü
        Bucket bucket = resolveBucket(resendCodeRequest.getUsername());
        if (bucket.tryConsume(1)) { // 1 hak tüketmeye çalış
            String username = resendCodeRequest.getUsername();
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

            if (userDetails == null) {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: User not found!"));
            }

            String newVerificationCode = emailService.sendVerificationCode(userDetails.getEmail());
            verificationService.storeVerificationCode(username, newVerificationCode);

            return ResponseEntity.ok(new MessageResponse("Yeni doğrulama kodu gönderildi."));
        } else {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(new MessageResponse("Error: Too many resend attempts. Please try again later."));
        }
    }


    @GetMapping("/check-auth")
    public ResponseEntity<?> checkAuth(@CookieValue(value = "jwt", required = false) String token, @RequestHeader("User-Agent") String userAgent) {
        if (token == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse("JWT cookie is missing"));
        }

        try {
            // Token doğrulama
            if (jwtUtils.validateJwtToken(token, userAgent)) {
                String username = jwtUtils.getUserNameFromJwtToken(token);
                UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
                return ResponseEntity.ok("Token is valid. User: " + userDetails.getUsername());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid or expired token!"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Error: Unauthorized"));
        }
    }
}
