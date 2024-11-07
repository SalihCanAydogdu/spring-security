package com.example.spring_security.security.services;


import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;





@Service
public class VerificationService {

	// We can associate codes with username or ID
    private Map<String, VerificationCode> verificationCodes = new ConcurrentHashMap<>();

    // Store the verification code (associated with the username)
    public void storeVerificationCode(String username, String code) {
        verificationCodes.put(username, new VerificationCode(code, LocalDateTime.now().plusMinutes(2)));
    }

    // Check the verification code (verify with username)
    public boolean isCodeValid(String username, String code) {
        VerificationCode verificationCode = verificationCodes.get(username);

        if (verificationCode == null) {
            return false;
        }

        // If the code is expired, delete it and consider it invalid
        if (verificationCode.getExpiryTime().isBefore(LocalDateTime.now())) {
            verificationCodes.remove(username);
            return false;
        }

        return verificationCode.getCode().equals(code);
    }

    private static class VerificationCode {
        private String code;
        private LocalDateTime expiryTime;

        public VerificationCode(String code, LocalDateTime expiryTime) {
            this.code = code;
            this.expiryTime = expiryTime;
        }

        public String getCode() {
            return code;
        }

        public LocalDateTime getExpiryTime() {
            return expiryTime;
        }
    }
    
    public String getUsernameFromCode(String code) {
    	// Necessary operations for verification of the code
        for (Map.Entry<String, VerificationCode> entry : verificationCodes.entrySet()) {
            if (entry.getValue().getCode().equals(code) && entry.getValue().getExpiryTime().isAfter(LocalDateTime.now())) {
                return entry.getKey(); // return username
            }
        }
        return null;
    }

    
    
}
