package com.example.oauth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;


@RestController
@RequestMapping("/api")
public class EmployeeController {

    @GetMapping("/employee")
    @PreAuthorize("hasRole('EMPLOYEE')")
    public Mono<String> helloUser() {
        return Mono.just("Hello Employee!");
    }
}
