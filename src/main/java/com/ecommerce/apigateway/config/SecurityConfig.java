package com.ecommerce.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * 1. Validate all requests with JWT.
 * 2. Set whitelist endpoints.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                // disable CSRF (we use JWT, which is stateless)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // core security rules
                .authorizeExchange(exchange -> exchange

                        // whitelist endpoints
                        .pathMatchers("/api/v1/users/register").permitAll()
                        .pathMatchers("/api/v1/users/login").permitAll()
                        .pathMatchers("/.well-known/jwks.json").permitAll()

                        // protect all other requests
                        .anyExchange().authenticated())

                // enable JWT validation, it will automatically read the "issuer-uri" from
                // application.yaml, and use default JWT validator.
                .oauth2ResourceServer(server -> server
                        .jwt(jwt -> {
                        }));

        return http.build();
    }
}
