package org.ajaxer.springframework.auth.server.security;

import java.util.List;

/**
 * A customizer interface that allows applications to contribute additional security rules
 * (e.g., public URLs, role-based access rules) to the security configuration.
 * <p>
 * This interface is meant to be implemented by library consumers who want to append or override
 * certain {@link SecurityRule}s used in `authorizeHttpRequests` configuration of Spring Security.
 *
 * <p><b>Example usage:</b>
 * <pre>{@code
 * @Component
 * public class MySecurityRules implements SecurityRulesCustomizer {
 *
 *     @Override
 *     public void customize(List<SecurityRule> rules) {
 *         rules.add(SecurityRule.permitAll(HttpMethod.GET, "/user/details"));
 *         rules.add(SecurityRule.hasRole("ADMIN", "/admin/**"));
 *     }
 * }
 * }</pre>
 * <p>
 * This ensures that your custom rules (e.g. `/user/details`, `/admin/**`) are merged with the starter’s defaults (e.g. `/actuator/**`),
 * rather than replacing them entirely.
 *
 * @author Shakir Ansari
 * @since 2025-07-27
 */
@FunctionalInterface
public interface SecurityRulesCustomizer
{
	void customize(List<SecurityRule> rules);
}

