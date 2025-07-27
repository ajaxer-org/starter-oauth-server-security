package org.ajaxer.springframework.auth.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * @author Shakir Ansari
 * @since 2025-07-26
 */
@Data
@ConfigurationProperties(prefix = "org.ajaxer.oauth-server")
public class OAuthServerProperties
{
	public static final String REQUEST_UUID = "org.ajaxer.oauth-server.request-id";

	private String oauthServerBaseUrl = "https://backend.ajaxer.org/auth2"; // no trailing slash
	private String jwkUrl = "/.well-known/jwks.json";

	/**
	 * List of public URIs to skip authentication filter.
	 */
	private List<String> publicUris;

	/**
	 * Length of the masked JWT token.
	 */
	public int maskedJwtTokenLength = 30;
}
