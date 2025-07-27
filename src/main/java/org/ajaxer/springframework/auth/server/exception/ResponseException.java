package org.ajaxer.springframework.auth.server.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;

/**
 * @author Shakir Ansari
 * @since 2025-07-18
 */
@Getter
public class ResponseException extends AuthenticationException
{
	private final HttpStatus httpStatus;
	private final String message;

	public ResponseException(String message, HttpStatus httpStatus)
	{
		super(message);
		this.message = message;
		this.httpStatus = httpStatus;
	}

	public static ResponseException badRequest(String message)
	{
		return new ResponseException(message, HttpStatus.BAD_REQUEST);
	}

	public static ResponseException unauthorized(String message)
	{
		return new ResponseException(message, HttpStatus.UNAUTHORIZED);
	}

	public static ResponseException forbidden(String message)
	{
		return new ResponseException(message, HttpStatus.FORBIDDEN);
	}

	public static ResponseException notFound(String message)
	{
		return new ResponseException(message, HttpStatus.NOT_FOUND);
	}

	public static ResponseException conflict(String message)
	{
		return new ResponseException(message, HttpStatus.CONFLICT);
	}

	public static ResponseException internalServerError(String message)
	{
		return new ResponseException(message, HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
