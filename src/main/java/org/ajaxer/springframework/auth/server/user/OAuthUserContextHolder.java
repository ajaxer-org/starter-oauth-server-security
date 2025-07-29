package org.ajaxer.springframework.auth.server.user;

import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

/**
 * @author Shakir Ansari
 * @since 2025-07-26
 */
@Slf4j
public class OAuthUserContextHolder
{
	private static final ThreadLocal<OAuthUser> userContext = new ThreadLocal<>();

	public static void set(OAuthUser OAuthUser)
	{
		if (log.isDebugEnabled())
			log.debug("Setting OAuthUser: {} in UserContext for threadId: {}", userContext, Thread.currentThread().getName());
		userContext.set(OAuthUser);
	}

	public static Optional<OAuthUser> get()
	{
		return Optional.ofNullable(userContext.get());
	}

	public static void clear()
	{
		if (log.isDebugEnabled())
			log.debug("Clearing UserContext for threadId: {}", Thread.currentThread().getName());
		userContext.remove();
	}
}
