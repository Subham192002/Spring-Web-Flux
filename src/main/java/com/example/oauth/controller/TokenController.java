package com.example.oauth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/custom-auth")
@RequiredArgsConstructor
public class TokenController {

    private final ReactiveAuthenticationManager authenticationManager;
    private final RegisteredClientRepository clientRepo;
    private final OAuth2AuthorizationService authService;

    @PostMapping("/token")
    public Mono<Map<String, Object>> generateToken(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        RegisteredClient client = clientRepo.findByClientId("my-client");

        return authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(username, password))
                .flatMap(auth -> {
                    Instant now = Instant.now();
                    OAuth2AccessToken token = new OAuth2AccessToken(
                            OAuth2AccessToken.TokenType.BEARER,
                            UUID.randomUUID().toString(),
                            now,
                            now.plusSeconds(1800),
                            client.getScopes()
                    );

                    OAuth2Authorization authorization = OAuth2Authorization
                            .withRegisteredClient(client)
                            .principalName(username)
                            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                            .token(token)
                            .build();

                    authService.save(authorization);

                    Map<String, Object> response = new HashMap<>();
                    response.put("access_token", token.getTokenValue());
                    response.put("token_type", "Bearer");
                    response.put("expires_in", 3600);

                    return Mono.just(response);
                });
    }
    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<Map<String, Object>> introspect(ServerWebExchange exchange) {
        return exchange.getFormData()
                .flatMap(formData -> {
                    String token = formData.getFirst("token");

                    return Mono.justOrEmpty(authService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN))
                            .map(auth -> {
                                Map<String, Object> response = new LinkedHashMap<>();
                                response.put("active", true);
                                response.put("username", auth.getPrincipalName());
                                response.put("exp", auth.getAccessToken().getToken().getExpiresAt().toString());
                                response.put("iat", auth.getAccessToken().getToken().getIssuedAt().toString());
                                response.put("scope", String.join(" ", auth.getAuthorizedScopes()));
                                return response;
                            })
                            .switchIfEmpty(Mono.just(Map.of("active", false)));
                });
    }


}
