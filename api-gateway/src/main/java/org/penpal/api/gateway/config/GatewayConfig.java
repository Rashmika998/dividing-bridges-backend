package org.penpal.api.gateway.config;

import org.penpal.api.gateway.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class GatewayConfig {
    @Autowired
    private JwtAuthenticationFilter filter;
    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("AUTH-SERVICE", r -> r.path("/api/auth/**").filters(f -> f.filter(filter)).uri("lb://AUTH-SERVICE"))
                .route("EMAIL-SERVICE", r -> r.path("/api/email-threads/**").filters(f -> f.filter(filter)).uri("lb://EMAIL-SERVICE"))
                .route("INVITATION-SERVICE", r -> r.path("/api/invitations/**").filters(f -> f.filter(filter)).uri("lb://INVITATION-SERVICE"))
                .route("EMAIL-SENDING-SERVICE", r -> r.path("/api/email-sending/**").filters(f -> f.filter(filter)).uri("lb://EMAIL-SENDING-SERVICE"))
                .route("PAYMENT-SERVICE", r -> r.path("/api/payments/**").filters(f -> f.filter(filter)).uri("lb://PAYMENT-SERVICE"))
                .route("DISCOVERY-SERVER", r -> r.path("/eureka/web").filters(f -> f.setPath("/")).uri("http://localhost:8761"))
                .route("DISCOVERY-SERVER-STATIC", r -> r.path("/eureka/**").uri("http://localhost:8761"))
                .build();
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of("https://bridge-divides.web.app", "http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
