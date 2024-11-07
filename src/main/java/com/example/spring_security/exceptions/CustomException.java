package com.example.spring_security.exceptions;


import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class CustomException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public CustomException(String message) {
        super(message);
    }
}
