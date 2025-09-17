package se.example.springcloud.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final String issuerUri;

    public SecurityConfig(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
        this.issuerUri = issuerUri;
    }

 @Bean
  SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .authorizeExchange()
        .pathMatchers("/headerrouting/**").permitAll()
        .pathMatchers("/actuator/**").permitAll()
        .pathMatchers("/eureka/**").permitAll()
        .pathMatchers("/oauth2/**").permitAll()
        .pathMatchers("/login/**").permitAll()
        .pathMatchers("/error/**").permitAll()
        .pathMatchers("/openapi/**").permitAll()
        .pathMatchers("/webjars/**").permitAll()
        .anyExchange().authenticated()
        .and()
      .oauth2ResourceServer()
        .jwt();
    return http.build();
  }

}
