package org.ajaxer.springframework.auth.server;

import lombok.extern.slf4j.Slf4j;
import org.ajaxer.springframework.auth.server.config.OAuthServerProperties;
import org.ajaxer.springframework.auth.server.filter.OAuthServerJwtAuthenticationFilter;
import org.ajaxer.springframework.auth.server.service.OAuthServerJwtService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Shakir Ansari
 * @since 2025-07-26
 */
@Slf4j
@Configuration
@ConditionalOnMissingBean(OAuthServerJwtAuthenticationFilter.class)
@EnableConfigurationProperties(OAuthServerProperties.class)
public class OAuthAutoConfiguration
{
	@Bean
	public OAuthServerJwtAuthenticationFilter oAuthServerJwtAuthenticationFilter(OAuthServerJwtService OAuthServerJwtService,
	                                                                             OAuthServerProperties properties)
	{
		if (log.isDebugEnabled())
			log.debug("Creating OAuthServerJwtAuthenticationFilter bean with properties: {}", properties);
		return new OAuthServerJwtAuthenticationFilter(OAuthServerJwtService, properties);
	}
}
