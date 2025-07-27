package org.ajaxer.springframework.auth.server.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Interface to allow user-defined customization of Spring Security's {@link HttpSecurity} object
 * after the default configuration provided by the security starter.
 * <p>
 * To customize security behavior, implement this interface in your Spring Boot application:
 *
 * <pre>{@code
 * @Component
 * public class MySecurityCustomizer implements SecurityCustomizer {
 *
 *     @Override
 *     public void customize(HttpSecurity http) throws Exception {
 *         // Example: Allow H2 console to be embedded in iframe
 *         http.headers(headers -> headers.frameOptions().sameOrigin());
 *
 *         // Example: Permit public access to actuator and docs
 *         http.authorizeHttpRequests(authz -> authz
 *             .requestMatchers("/actuator/**", "/docs/**").permitAll()
 *         );
 *     }
 * }
 * }</pre>
 *
 * <p>
 * ⚠️ Note: If you override `authorizeHttpRequests`, make sure to maintain existing rules
 * or coordinate with the starter’s configuration to avoid unintentionally blocking endpoints.
 *
 * @author Shakir Ansari
 * @since 2025-07-27
 */
@FunctionalInterface
public interface SecurityCustomizer
{

	/**
	 * Customize the {@link HttpSecurity} instance after the starter's defaults have been applied.
	 *
	 * @param http the {@link HttpSecurity} object to modify
	 * @throws Exception in case of configuration errors
	 */
	void customize(HttpSecurity http) throws Exception;
}
