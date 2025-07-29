package org.ajaxer.springframework.auth.server.filter;

import jakarta.servlet.Filter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * @author Shakir Ansari
 * @since 2025-07-27
 */
public record OAuthServerFilterConfigurer(
		Filter filter,
		Class<? extends Filter> relativeTo,
		FilterInsertionPoint insertionPoint
)
{
	public static OAuthServerFilterConfigurer defaultRegistration(Filter filter)
	{
		return new OAuthServerFilterConfigurer(filter, UsernamePasswordAuthenticationFilter.class, FilterInsertionPoint.BEFORE);
	}
}

