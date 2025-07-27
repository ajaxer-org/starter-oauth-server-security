package org.ajaxer.springframework.auth.server.security;

import lombok.RequiredArgsConstructor;
import org.ajaxer.springframework.auth.server.config.OAuthServerProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author Shakir Ansari
 * @since 2025-07-27
 */
@Component
@RequiredArgsConstructor
public class PublicURISecurityRulesCustomizer implements SecurityRulesCustomizer
{
	private final OAuthServerProperties properties;

	@Override
	public void customize(List<SecurityRule> rules)
	{
		if (properties.getPublicUris() == null)
			return;

		properties.getPublicUris().forEach(publicURI -> rules.add(SecurityRule.permitAll(publicURI)));
	}
}
