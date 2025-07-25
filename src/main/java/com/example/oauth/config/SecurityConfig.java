package com.example.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

    // In-memory users for fallback login (not used in token auth)
    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}user").roles("USER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}admin").roles("ADMIN").build();
        return new MapReactiveUserDetailsService(user, admin);
    }

    // WebClient for calling /introspect
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    // Main security filter chain
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth -> auth
                        .pathMatchers("/custom-auth/token", "/custom-auth/introspect").permitAll()
                        .pathMatchers("/api/user/**").hasRole("USER")
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .opaqueToken(token -> token.introspector(customIntrospector(webClientBuilder())))
                )
                .build();
    }

    // Introspects token using your custom-auth endpoint and assigns roles
    @Bean
    public ReactiveOpaqueTokenIntrospector customIntrospector(WebClient.Builder webClientBuilder) {
        WebClient webClient = webClientBuilder.build();

        return token -> webClient
                .post()
                .uri("http://localhost:8080/custom-auth/introspect")
                .header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .bodyValue("token=" + token)
                .retrieve()
                .bodyToMono(Map.class)
                .flatMap(attributes -> {
                    boolean active = (Boolean) attributes.getOrDefault("active", false);
                    if (!active) return Mono.empty();

                    String username = (String) attributes.get("username");

                    // Convert "exp" and "iat" from String to Instant
                    Instant exp = Instant.parse((String) attributes.get("exp"));
                    Instant iat = Instant.parse((String) attributes.get("iat"));

                    List<GrantedAuthority> authorities = switch (username) {
                        case "admin" -> List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
                        case "user" -> List.of(new SimpleGrantedAuthority("ROLE_USER"));
                        default -> List.of();
                    };

                    Map<String, Object> enhancedAttributes = Map.of(
                            "username", username,
                            "exp", exp,
                            "iat", iat,
                            "scope", attributes.getOrDefault("scope", "")
                    );

                    return Mono.just(new OAuth2AuthenticatedPrincipal() {
                        @Override
                        public Map<String, Object> getAttributes() {
                            return enhancedAttributes;
                        }

                        @Override
                        public Collection<? extends GrantedAuthority> getAuthorities() {
                            return authorities;
                        }

                        @Override
                        public String getName() {
                            return username;
                        }
                    });
                });
    }

    // Fallback auth manager (not used unless manually logging in)
    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    }

    // In-memory auth storage (only used if you're issuing tokens too)
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }
}
