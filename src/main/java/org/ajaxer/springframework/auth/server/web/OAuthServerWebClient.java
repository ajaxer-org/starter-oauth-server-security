package org.ajaxer.springframework.auth.server.web;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.springframework.auth.server.config.OAuthServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Shakir Ansari
 * @since 2025-07-24
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthServerWebClient
{
	private final RestTemplateBuilder restTemplateBuilder;

	private final OAuthServerProperties properties;

	private RestTemplate restTemplate;

	@PostConstruct
	public void init()
	{
		if (log.isDebugEnabled())
			log.debug("Initializing OAuthServerWebClient with base URL: {}", properties.getOauthServerBaseUrl());
		this.restTemplate = restTemplateBuilder.rootUri(properties.getOauthServerBaseUrl()).build();
	}

	public String jwksJson(String kid)
	{
		log.debug("Fetching JWKS JSON with kid: {}", kid);

		try
		{
			var jwkUrl = properties.getJwkUrl();
			log.debug("Initial JWKS URL: {}", jwkUrl);

			if (jwkUrl.startsWith(properties.getOauthServerBaseUrl()))
				jwkUrl = jwkUrl.substring(properties.getOauthServerBaseUrl().length());
			log.debug("Fetching JWKS JSON from URL: {}", jwkUrl);

			UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromPath("/.well-known/jwks.json");

			if (kid != null && !kid.isBlank())
				uriBuilder.queryParam("kid", kid);

			var uri = uriBuilder.toUriString();
			log.debug("Constructed URI for JWKS: {}", uri);

			ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
			if (log.isDebugEnabled())
				log.debug("Response from JWKS: {}", response);

			if (response.getStatusCode().is2xxSuccessful())
				return response.getBody();

			throw new RuntimeException("Failed to fetch JWKS JSON: " + response.getStatusCode());
		} catch (Exception e)
		{
			log.error("Error fetching JWKS JSON", e);
			throw new RuntimeException("Error fetching JWKS JSON", e);
		}
	}
}

