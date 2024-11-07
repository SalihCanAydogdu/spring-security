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
    private UserDetailsServiceImpl userDetailsService; // To authenticate the user with username

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    // A map to hold buckets per user
    private final Map<String, Bucket> bucketCache = new ConcurrentHashMap<>();

    @Autowired
    public AuthController(TokenBlackListService tokenBlackListService, RoleRepository roleRepository, VerificationService verificationService,
                          EmailService emailService) {
        this.tokenBlackListService = tokenBlackListService;
        this.roleRepository = roleRepository;
        this.verificationService = verificationService;
        this.emailService = emailService;
    }

    // A method that sets rate limits for each user
    private Bucket resolveBucket(String username) {
        return bucketCache.computeIfAbsent(username, key -> createNewBucket());
    }

    private Bucket createNewBucket() {
        Refill refill = Refill.intervally(5, Duration.ofMinutes(10)); // 5 requests in 10 minutes
        Bandwidth limit = Bandwidth.classic(5, refill); // Sets the bandwidth limit
        return Bucket.builder().addLimit(limit).build(); // Creates a new bucket
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

        // Let's add the token to the blacklist
        tokenBlackListService.add(token);

        // Clear cookie (delete cookie with Max-Age=0)
        String cookie;
        String env = System.getenv("SPRING_PROFILES_ACTIVE"); // Check environment variable
        if ("prod".equals(env)) {
        	// Secure and SameSite=None for production environment
            cookie = "jwt=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0";
        } else {
        	// For development environment Secure=false and SameSite=Lax
            cookie = "jwt=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
        }

        response.setHeader("Set-Cookie", cookie);

        return ResponseEntity.ok("Logout successful!");
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SigninRequest signinRequest, @RequestHeader("User-Agent") String userAgent) {
    	// Rate Limiting control
        Bucket bucket = resolveBucket(signinRequest.getUsername());
        if (bucket.tryConsume(1)) { // Try to use up 1 right
            try {
            	// Authenticate the user
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(signinRequest.getUsername(), signinRequest.getPassword())
                );

                // Add authentication to security context
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Get user details
                UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

                // Generate verification code and send via email
                String verificationCode = emailService.sendVerificationCode(userDetails.getEmail());
                if (verificationCode == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new MessageResponse("Error: Verification code could not be sent."));
                }

                // Save verification code
                verificationService.storeVerificationCode(userDetails.getUsername(), verificationCode);

                // Return successful response
                return ResponseEntity.ok(new MessageResponse("Signin successful and verification code sent to email."));

            } catch (Exception e) {
                // Return appropriate response on error
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

     // Create JWT token (with device information)
        String jwt = jwtUtils.generateJwtTokenWithDevice(authentication, userAgent);

        // Cookie settings
        String env = System.getenv("SPRING_PROFILES_ACTIVE"); // Control the environment with environment variables
        String cookie;
        if ("prod".equals(env)) {
        	// For production environment
            cookie = String.format("jwt=%s; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=%d", jwt, 4 * 60 * 60);
        } else {
        	// For development environment
            cookie = String.format("jwt=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d", jwt, 4 * 60 * 60);
        }

        response.setHeader("Set-Cookie", cookie);

        return ResponseEntity.ok(new MessageResponse("Verification successful and JWT stored in cookie."));
    }

    @PostMapping("/resend-code")
    public ResponseEntity<?> resendVerificationCode(@RequestBody ResendCodeRequest resendCodeRequest) {
    	// Rate Limiting control
        Bucket bucket = resolveBucket(resendCodeRequest.getUsername());
        if (bucket.tryConsume(1)) { // Try to use up 1 right
            String username = resendCodeRequest.getUsername();
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

            if (userDetails == null) {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: User not found!"));
            }

            String newVerificationCode = emailService.sendVerificationCode(userDetails.getEmail());
            verificationService.storeVerificationCode(username, newVerificationCode);

            return ResponseEntity.ok(new MessageResponse("New verification code has been sent."));
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
        	// Token verification
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
