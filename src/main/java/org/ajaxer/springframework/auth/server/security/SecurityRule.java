package org.ajaxer.springframework.auth.server.security;

import org.springframework.http.HttpMethod;

/**
 * @author Shakir Ansari
 * @since 2025-07-27
 */
public record SecurityRule(HttpMethod method, String pattern, Access access)
{
	public static SecurityRule permitAll(String pattern)
	{
		return new SecurityRule(null, pattern, Access.PERMIT_ALL);
	}

	public static SecurityRule authenticated(String pattern)
	{
		return new SecurityRule(null, pattern, Access.AUTHENTICATED);
	}

	public static SecurityRule hasRole(String pattern, String role)
	{
		return new SecurityRule(null, pattern, Access.hasRole(role));
	}

	public static SecurityRule with(HttpMethod method, String pattern, Access access)
	{
		return new SecurityRule(method, pattern, access);
	}
}
