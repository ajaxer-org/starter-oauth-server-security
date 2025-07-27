package org.ajaxer.springframework.auth.server.security;

/**
 * @author Shakir Ansari
 * @since 2025-07-27
 */
public sealed interface Access permits Access.PermitAll, Access.Authenticated, Access.Role
{
	record PermitAll() implements Access {}

	record Authenticated() implements Access {}

	record Role(String role) implements Access {}

	Access PERMIT_ALL = new PermitAll();

	Access AUTHENTICATED = new Authenticated();

	static Access hasRole(String role)
	{
		return new Role(role);
	}
}

