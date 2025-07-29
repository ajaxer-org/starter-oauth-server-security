package org.ajaxer.springframework.auth.server.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.simple.utils.CollectionUtils;
import org.ajaxer.simple.utils.StringUtils;
import org.ajaxer.springframework.auth.server.config.OAuthServerProperties;
import org.ajaxer.springframework.auth.server.exception.ResponseException;
import org.ajaxer.springframework.auth.server.service.OAuthServerJwtService;
import org.ajaxer.springframework.auth.server.user.OAuthUser;
import org.ajaxer.springframework.auth.server.user.OAuthUserContextHolder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static org.ajaxer.springframework.auth.server.config.OAuthServerProperties.REQUEST_UUID;

/**
 * @author Shakir Ansari
 * @since 2025-07-25
 */
@Slf4j
public class OAuthServerJwtAuthenticationFilter extends OncePerRequestFilter
{
	private final AntPathMatcher pathMatcher = new AntPathMatcher();
	private final OAuthServerJwtService oAuthServerJwtService;
	private final OAuthServerProperties properties;

	public OAuthServerJwtAuthenticationFilter(OAuthServerJwtService oAuthServerJwtService, OAuthServerProperties properties)
	{
		log.debug("Creating OAuthServerJwtAuthenticationFilter with properties: {}", properties);

		this.oAuthServerJwtService = oAuthServerJwtService;
		this.properties = properties;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request)
	{
		log.debug("shouldNotFilter invoked for requestURI: {}", request.getRequestURI());

		if (properties.getPublicUris() != null)
		{
			String path = request.getServletPath();
			log.debug("Checking if path '{}' matches any public URIs", path);

			for (String pattern : properties.getPublicUris())
			{
				if (pathMatcher.match(pattern, path))
					return true;
			}
		}

		return false;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
	                                HttpServletResponse response,
	                                FilterChain filterChain) throws ServletException, IOException
	{
		log.debug("doFilterInternal called for request: {}", request.getRequestURI());

		try
		{
			String servletPath = request.getServletPath();
			log.info("[{}], servletPath: {}", request.getMethod().toUpperCase(), servletPath);

			log.debug("{}: {}", REQUEST_UUID, request.getHeader(REQUEST_UUID));

			String jwtToken = parseJwt(request);
			log.debug("jwtToken: {}", jwtToken);

			String subject = getSubject(jwtToken);

			String username = getUsername(jwtToken);

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			log.debug("Current authentication: {}", authentication);

			// Spring sets the anonymous user via the AnonymousAuthenticationFilter.
			if (authentication == null || authentication instanceof AnonymousAuthenticationToken)
			{
				UserDetails userDetails = User.builder()
				                              .username(subject)
				                              .password("") // Password is not relevant for token-based auth
				                              .authorities(rolesToAuthorities(getRoles(jwtToken))) // Or based on claims
				                              .build();

				var auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(auth);
				log.debug("setting SecurityContextHolder with authentication: {}", auth);

				OAuthUser oAuthUser = new OAuthUser(subject, username);
				OAuthUserContextHolder.set(oAuthUser);
				log.debug("Setting OAuthUserContextHolder with oAuthUser: {}", oAuthUser);
			}

			log.debug("before filterChain.doFilter(request, response)");
			filterChain.doFilter(request, response);
			log.debug("after filterChain.doFilter(request, response)");
		} finally
		{
			OAuthUserContextHolder.clear();
			log.debug("Cleared OAuthUserContextHolder");

			SecurityContextHolder.clearContext();
			log.debug("Cleared SecurityContextHolder");
		}
	}

	public String parseJwt(HttpServletRequest request)
	{
		String authorizationHeader = request.getHeader("Authorization");
		log.debug("authorizationHeader: {}", authorizationHeader);

		final String bearer = "Bearer ";
		if (authorizationHeader == null)
			throw ResponseException.unauthorized("Authorization header is missing");

		if (!authorizationHeader.startsWith(bearer))
			throw ResponseException.unauthorized("Authorization header should be Bearer");

		String jwtToken = authorizationHeader.substring(bearer.length());
		log.debug("jwtToken: {}", jwtToken);

		boolean verifiedJWT = oAuthServerJwtService.verifyJWT(jwtToken);
		log.info("verifyJWT: {}", verifiedJWT);

		if (!verifiedJWT)
			throw ResponseException.forbidden("access_token malformed");

		if (oAuthServerJwtService.isExpired(jwtToken))
			throw ResponseException.forbidden("access_token expired");

		return jwtToken;
	}

	public String getSubject(String jwtToken)
	{
		String subject = oAuthServerJwtService.getSubject(jwtToken);
		log.debug("subject: {}", subject);

		if (StringUtils.isBlank(subject))
			throw ResponseException.forbidden("access_token malformed");

		return subject;
	}

	public String getUsername(String jwtToken)
	{
		String username = oAuthServerJwtService.getClaimValue(jwtToken, "username");
		log.debug("username: {}", username);

		if (StringUtils.isBlank(username))
			throw ResponseException.forbidden("access_token malformed");

		return username;
	}

	public List<SimpleGrantedAuthority> rolesToAuthorities(List<String> roles)
	{
		List<SimpleGrantedAuthority> authorities = roles
				.stream()
				// Add "ROLE_" prefix and ensure uppercase
				.map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
				.toList();
		log.debug("authorities: {}", authorities);

		return authorities;
	}

	public List<String> getRoles(String jwtToken)
	{
		List<String> roles = oAuthServerJwtService.getRoles(jwtToken);
		log.debug("roles: {}", roles);

		if (CollectionUtils.isBlank(roles))
			throw ResponseException.forbidden("roles are missing");

		return roles;
	}
}
