package org.ajaxer.springframework.auth.server.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.springframework.auth.server.config.OAuthServerProperties;
import org.ajaxer.springframework.auth.server.dto.JwtHeader;
import org.springframework.stereotype.Service;

import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * @author Shakir Ansari
 * @since 2025-04-24
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthServerJwtService
{
	public static final String TOKEN_TYPE_BEARER = "Bearer ";

	private final ObjectMapper objectMapper;
	private final OAuthServerJwkService OAuthServerJwkService;
	private final OAuthServerProperties properties;

	public boolean verifyJWT(String token)
	{
		if (log.isDebugEnabled())
			log.debug("Verifying JWT token: {}", getMaskedJwtToken(token, properties.maskedJwtTokenLength));

		try
		{
			JwtHeader jwtHeader = extractHeader(token);
			log.debug("JWT Header: kid={}, alg={}", jwtHeader.kid, jwtHeader.alg);

			RSAPublicKey rsaPublicKey = OAuthServerJwkService.getRsaPublicKey(jwtHeader.kid);
			if (log.isDebugEnabled())
				log.debug("RSA Public Key: {}", rsaPublicKey);

			Signature signature = Signature.getInstance(mapJwtAlgToJava(jwtHeader.alg));
			if (log.isDebugEnabled())
				log.debug("Using signature algorithm: {}", signature.getAlgorithm());

			signature.initVerify(rsaPublicKey);
			log.debug("Signature initialized with RSA public key");

			// Split token into header, payload, and signature
			String[] parts = token.split("\\.");
			if (parts.length != 3)
				return false; // Invalid JWT

			String data = parts[0] + "." + parts[1]; // Header and Payload
			byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

			signature.update(data.getBytes());
			return signature.verify(signatureBytes);
		} catch (Exception e)
		{
			log.error("Failed to verify JWT token", e);
			return false;
		}
	}

	private String mapJwtAlgToJava(String alg)
	{
		if (log.isDebugEnabled())
			log.debug("Mapping JWT algorithm '{}' to Java signature algorithm", alg);

		return switch (alg)
		{
			case "RS256" -> "SHA256withRSA";
			case "RS384" -> "SHA384withRSA";
			case "RS512" -> "SHA512withRSA";

			case "ES256" -> "SHA256withECDSA";
			case "ES384" -> "SHA384withECDSA";
			case "ES512" -> "SHA512withECDSA";

			default -> throw new UnsupportedOperationException("Unsupported or insecure JWT algorithm: " + alg);
		};
	}

	public JwtHeader extractHeader(String jwtToken)
	{
		if (log.isDebugEnabled())
			log.debug("Extracting JWT header from token: {}", getMaskedJwtToken(jwtToken, properties.maskedJwtTokenLength));

		try
		{
			String[] parts = jwtToken.split("\\.");
			if (log.isDebugEnabled())
				log.debug("JWT parts lenght: {}", parts.length);

			if (parts.length < 2)
				throw new IllegalArgumentException("Invalid JWT format");

			String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
			if (log.isDebugEnabled())
				log.debug("Decoded JWT header JSON: {}", headerJson);

			JsonNode headerNode = objectMapper.readTree(headerJson);
			if (log.isDebugEnabled())
				log.debug("Parsed JWT header JSON: {}", headerNode);

			String kid = headerNode.path("kid").asText(null);
			if (log.isDebugEnabled())
				log.debug("Extracted kid: {}", kid);

			String alg = headerNode.path("alg").asText(null);
			if (log.isDebugEnabled())
				log.debug("Extracted alg: {}", alg);

			return JwtHeader.builder().kid(kid).alg(alg).build();
		} catch (Exception e)
		{
			throw new RuntimeException("Failed to extract JWT header", e);
		}
	}

	public Map<String, Object> getClaims(String token)
	{
		if (log.isDebugEnabled())
			log.debug("Getting claims from JWT token: {}", getMaskedJwtToken(token, properties.maskedJwtTokenLength));

		try
		{
			String[] parts = token.split("\\.");
			if (log.isDebugEnabled())
				log.debug("JWT parts length: {}", parts.length);

			if (parts.length != 3)
				return null;

			String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
			if (log.isDebugEnabled())
				log.debug("Decoded JWT payload JSON: {}", getMaskedJwtToken(payloadJson, properties.maskedJwtTokenLength));

			return objectMapper.readValue(payloadJson, new TypeReference<>() {});
		} catch (Exception e)
		{
			log.error("Failed to parse JWT claims", e);
			return null;
		}
	}

	public DecodedJWT decodeToken(String token)
	{
		if (log.isDebugEnabled())
			log.debug("Decoding JWT token: {}", getMaskedJwtToken(token, properties.maskedJwtTokenLength));

		if (token.startsWith(TOKEN_TYPE_BEARER))
		{
			log.debug("Removing Bearer prefix from token");
			token = token.substring(TOKEN_TYPE_BEARER.length());
		}

		return JWT.decode(token);
	}

	public String getClaimValue(String token, String claimName)
	{
		log.debug("Getting claim value: {}", claimName);
		return decodeToken(token).getClaim(claimName).asString();
	}

	public <T> T getClaimValue(String token, String claimName, Class<T> requiredType)
	{
		log.debug("Getting claim value: {} as type: {}", claimName, requiredType.getSimpleName());
		return decodeToken(token).getClaim(claimName).as(requiredType);
	}

	public List<String> getClaimValueAsList(String token, String claimName)
	{
		log.debug("Getting claim value as list: {}", claimName);
		return decodeToken(token).getClaim(claimName).asList(String.class);
	}

	public <T> List<T> getClaimValueAsList(String token, String claimName, Class<T> requiredType)
	{
		log.debug("Getting claim value as list: {} with type: {}", claimName, requiredType.getSimpleName());
		return decodeToken(token).getClaim(claimName).asList(requiredType);
	}

	// Method to get all claims
	private Map<String, Claim> extractAllClaims(String token)
	{
		if (log.isDebugEnabled())
			log.debug("Extracting all claims from JWT token: {}", getMaskedJwtToken(token, properties.maskedJwtTokenLength));
		return decodeToken(token).getClaims();
	}

	@SuppressWarnings("unchecked")
	public List<String> getRoles(String token)
	{
		if (log.isDebugEnabled())
			log.debug("Getting roles from JWT token: {}", getMaskedJwtToken(token, properties.maskedJwtTokenLength));
		return getClaimValue(token, "roles", List.class);
	}

	public String getSubject(String jwtToken)
	{
		if (log.isDebugEnabled())
			log.debug("Getting subject from JWT token: {}", getMaskedJwtToken(jwtToken, properties.maskedJwtTokenLength));
		return decodeToken(jwtToken).getSubject();
	}

	public boolean isExpired(String token)
	{
		Instant expiresAtAsInstant = decodeToken(token).getExpiresAtAsInstant();

		if (log.isDebugEnabled())
			log.debug("Token expires at: {}, now: {}", expiresAtAsInstant, Instant.now());

		return expiresAtAsInstant.isBefore(Instant.now());
	}

	public static String getMaskedJwtToken(String jwt, int maskedJwtTokenLength)
	{
		return jwt.length() > maskedJwtTokenLength ? jwt.substring(0, maskedJwtTokenLength) + "..." : jwt;
	}
}
