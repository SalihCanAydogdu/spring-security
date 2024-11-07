package com.example.spring_security.security.services;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public String sendVerificationCode(String to) {
        String verificationCode = generateVerificationCode();
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Doğrulama Kodu");
        message.setText("Doğrulama Kodunuz: " + verificationCode);
        
        try {
            mailSender.send(message);
        } catch (Exception e) {
            return null;
        }
        
        return verificationCode;
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // A random 6 digit number
        return String.valueOf(code);
    }
}
