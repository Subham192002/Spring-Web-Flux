package com.example.oauth.controller;

import com.example.oauth.dto.BookDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/api/user")
@Slf4j
public class UserController {

    @GetMapping("/hello")
    @PreAuthorize("hasRole('USER')")
    public Mono<String> helloUser() {
        return Mono.just("Hello USER!");
    }

    @GetMapping("/stream")
    @PreAuthorize("hasRole('USER')")
    public Flux<BookDto> userDataStream() {
        return Flux.fromIterable(books)
                .delayElements(Duration.ofSeconds(1)) // simulate streaming
                .doOnNext(book -> log.info("Sending: {}", book.getTitle()))
                .onErrorResume(e -> {
                    log.error("Error while streaming books", e);
                    return Flux.empty(); // or return fallback Flux
                });
    }

    private final List<BookDto> books = List.of(
            new BookDto("1", "Clean Code", "Robert C. Martin", 45.99),
            new BookDto("2", "Effective Java", "Joshua Bloch", 55.49),
            new BookDto("3", "Spring in Action", "Craig Walls", 49.99),
            new BookDto("4", "Java Concurrency in Practice", "Brian Goetz", 59.99)
    );
}