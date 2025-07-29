package org.ajaxer.springframework.auth.server.user;

import java.io.Serializable;

/**
 * Represents an OAuth authenticated user with a unique identifier and username.
 * <p>
 * This record is a simple data carrier used to pass user information
 * across different layers or components of an application.
 * </p>
 *
 * <p>
 * Implements {@link Serializable} for compatibility with serialization mechanisms.
 * </p>
 *
 * @param id Unique identifier for the user.
 * @param username Username of the user, typically used for login or display purposes.
 * @author Shakir
 * @version 2025-07-27
 */
public record OAuthUser(String id, String username) implements Serializable {}

