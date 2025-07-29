package org.ajaxer.springframework.auth.server.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.springframework.auth.server.config.OAuthServerAuthenticationEntryPoint;
import org.ajaxer.springframework.auth.server.filter.OAuthServerFilterConfigurer;
import org.ajaxer.springframework.auth.server.filter.OAuthServerJwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Shakir Ansari
 * @since 2025-07-25
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SpringSecurityConfig
{
	private final OAuthServerAuthenticationEntryPoint OAuthServerAuthenticationEntryPoint;
	private final OAuthServerJwtAuthenticationFilter oAuthServerJwtAuthenticationFilter;
	private final List<SecurityCustomizer> securityCustomizerList;
	private final List<SecurityRulesCustomizer> customizers;
	private final List<OAuthServerFilterConfigurer> OAuthServerFilterConfigurers;


	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	{
		log.debug("Creating SecurityFilterChain with HttpSecurity");
		final List<SecurityRule> securityRules = new ArrayList<>();
		for (SecurityRulesCustomizer customizer : customizers)
		{
			if (log.isDebugEnabled())
				log.debug("Customizing security rules with: {}", customizer.getClass().getSimpleName());

			customizer.customize(securityRules);
		}

		if (log.isDebugEnabled())
			log.debug("securityRules: {}", securityRules);

		// Disable CSRF (not needed for JWT)
		http.csrf(AbstractHttpConfigurer::disable);
		log.debug("DEFAULT: CSRF protection disabled");

		// Disable session-based authentication (stateless)
		http.sessionManagement(AbstractHttpConfigurer::disable);
		log.debug("DEFAULT: Session management disabled (stateless)");

		http.authorizeHttpRequests(registry -> {

			for (SecurityRule rule : securityRules)
			{
				if (log.isDebugEnabled())
					log.debug("Applying security rule: {} {}", rule.method(), rule.pattern());

				if (rule.method() != null)
				{
					if (rule.access() instanceof Access.PermitAll)
						registry.requestMatchers(rule.method(), rule.pattern()).permitAll();
					else if (rule.access() instanceof Access.Authenticated)
						registry.requestMatchers(rule.method(), rule.pattern()).authenticated();
					else if (rule.access() instanceof Access.Role role)
						registry.requestMatchers(rule.method(), rule.pattern()).hasRole(role.role());
				} else
				{
					if (rule.access() instanceof Access.PermitAll)
						registry.requestMatchers(rule.pattern()).permitAll();
					else if (rule.access() instanceof Access.Authenticated)
						registry.requestMatchers(rule.pattern()).authenticated();
					else if (rule.access() instanceof Access.Role role)
						registry.requestMatchers(rule.pattern()).hasRole(role.role());
				}
			}

			//registry.anyRequest().denyAll(); // fallback
			registry.anyRequest().authenticated(); // fallback
		});


		// allow H2 to be displayed in frames4
		http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
		log.debug("DEFAULT: Frame options set to same-origin for H2 console");

		// will take care of JWT authentication's exceptions like Unauthorized, Forbidden, etc.
		http.exceptionHandling(handler -> handler.authenticationEntryPoint(OAuthServerAuthenticationEntryPoint));
		log.debug("DEFAULT: Exception handling configured with OAuthServerAuthenticationEntryPoint");

		// Spring sets the anonymous user via the AnonymousAuthenticationFilter.
		// This way context will always be null
		http.anonymous(AbstractHttpConfigurer::disable);
		log.debug("DEFAULT: Anonymous authentication disabled");

		if (securityCustomizerList != null)
		{
			log.debug("Applying custom security customizers");
			for (SecurityCustomizer securityCustomizer : securityCustomizerList)
			{
				if (log.isDebugEnabled())
					log.debug("Customizing security with: {}", securityCustomizer.getClass().getSimpleName());
				securityCustomizer.customize(http);
			}
		} else
			log.debug("No custom security customizers found");

		http.addFilterBefore(oAuthServerJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		log.debug("DEFAULT: Added OAuthServerJwtAuthenticationFilter before UsernamePasswordAuthenticationFilter");

		if (OAuthServerFilterConfigurers != null)
		{
			log.debug("Applying OAuthServerFilterConfigurers");

			OAuthServerFilterConfigurers.forEach(registration -> {
				log.debug("Registering OAuthServerFilterConfigurer: {}", registration.getClass().getSimpleName());
				switch (registration.insertionPoint())
				{
					case BEFORE -> http.addFilterBefore(registration.filter(), registration.relativeTo());
					case AFTER -> http.addFilterAfter(registration.filter(), registration.relativeTo());
					case AT -> http.addFilterAt(registration.filter(), registration.relativeTo());
					case DEFAULT -> http.addFilterBefore(registration.filter(), UsernamePasswordAuthenticationFilter.class);
				}
			});
		} else
			log.debug("No OAuthServerFilterConfigurers found, using default filter registration");

		return http.build();
	}
}
