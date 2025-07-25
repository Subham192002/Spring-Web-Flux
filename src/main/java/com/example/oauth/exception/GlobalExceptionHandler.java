package com.example.oauth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public Mono<String> handleAccessDeniedException(AccessDeniedException ex) {
        log.error("Access denied: {}", ex.getMessage());
        return Mono.just("Access Denied: You don't have the required role.");
    }

    @ExceptionHandler(BadCredentialsException.class)
    public Mono<String> handleBadCredentials(BadCredentialsException ex) {
        log.error("Login failed: {}", ex.getMessage());
        return Mono.just("Invalid Username or password");
    }

}
