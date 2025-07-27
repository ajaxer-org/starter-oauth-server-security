package org.ajaxer.springframework.auth.server.annotation;

import org.ajaxer.springframework.auth.server.config.OAuthComponentScanConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enables JWT-based security configuration in a Spring Boot application.
 * <p>
 * This annotation imports {@link OAuthComponentScanConfiguration} which configures JWT filters,
 * exception handling, and predefined {@link org.springframework.security.config.annotation.web.builders.HttpSecurity}
 * rules like disabling sessions and CSRF, setting up authentication entry point,
 * and applying any provided {@code SecurityRulesCustomizer} implementations.
 * <p>
 * It allows the starter to be plug-and-play with sensible defaults, and
 * developers can still define additional security rules by creating beans that implement
 * {@code SecurityRulesCustomizer} or {@code SecurityCustomizer}.
 *
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * @SpringBootApplication
 * @EnableOAuthServerSecurity
 * public class MyApplication {
 *     public static void main(String[] args) {
 *         SpringApplication.run(MyApplication.class, args);
 *     }
 * }
 * }</pre>
 *
 * @author Shakir
 * @since 2025-07-25
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(OAuthComponentScanConfiguration.class)
public @interface EnableOAuthServerSecurity {}
