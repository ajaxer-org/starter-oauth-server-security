package org.ajaxer.springframework.auth.server.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.simple.utils.StringUtils;
import org.ajaxer.springframework.auth.server.web.OAuthServerWebClient;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Shakir Ansari
 * @since 2025-07-24
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthServerJwkService
{
	private final Map<String, RSAPublicKey> rsaPublicKeyMap = new ConcurrentHashMap<>();

	private final OAuthServerWebClient authServerWebClient;

	public RSAPublicKey getRsaPublicKey(String kid)
	{
		log.debug("Retrieving RSA public key for kid: {}", kid);

		if (StringUtils.isBlank(kid))
			throw new NullPointerException("kid cannot be null or blank");

		if (!rsaPublicKeyMap.containsKey(kid))
		{
			log.warn("Fetching RSA public key for kid: {}", kid);

			RSAPublicKey rsaPublicKey = fetchKeyFromAuthServer(kid);

			rsaPublicKeyMap.put(kid, rsaPublicKey);
		} else
			log.debug("RSA public key for kid: {} already cached", kid);

		return rsaPublicKeyMap.get(kid);
	}

	private RSAPublicKey fetchKeyFromAuthServer(String kid)
	{
		log.debug("Fetching RSA public key from auth server for kid: {}", kid);

		String rawJsonResponse = authServerWebClient.jwksJson(kid);
		log.debug("Raw JWKS response: {}", rawJsonResponse);

		return parseRsaPublicKey(rawJsonResponse, kid);
	}

	@SneakyThrows
	private RSAPublicKey parseRsaPublicKey(String jwksJson, String expectedKid)
	{
		log.debug("Parsing JWKS JSON: {}, with expectedKid: {}", jwksJson, expectedKid);

		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode root = objectMapper.readTree(jwksJson);
		log.debug("Parsed JSON root: {}", root);

		JsonNode keys = root.path("responseBody").path("keys");
		log.debug("Extracted keys node: {}", keys);
		if (!keys.isArray())
			throw new IllegalArgumentException("Invalid JWKS format: keys not found");

		JsonNode matchingKey = null;

		for (JsonNode key : keys)
		{
			String kid = key.path("kid").asText();
			log.debug("Processing key with kid: {} and expected kid: {}", kid, expectedKid);

			if (expectedKid == null || expectedKid.equals(kid))
			{
				matchingKey = key;
				break;
			}
		}

		if (matchingKey == null)
			throw new IllegalArgumentException("No matching key found for kid: " + expectedKid);

		String n = matchingKey.get("n").asText();
		log.debug("Modulus (n): {}", n);

		String e = matchingKey.get("e").asText();
		log.debug("Exponent (e): {}", e);

		// Decode Base64URL (not standard Base64)
		BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
		log.debug("Decoded modulus: {}", modulus);

		BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
		log.debug("Decoded exponent: {}", exponent);

		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
		log.debug("Created RSAPublicKeySpec with modulus: {}, exponent: {}", modulus, exponent);

		return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
	}
}
