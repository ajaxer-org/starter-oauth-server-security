package org.ajaxer.springframework.auth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.ajaxer.springframework.auth.server.dto.ErrorResponseDto;
import org.ajaxer.springframework.auth.server.exception.ResponseException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author Shakir Ansari
 * @since 2025-07-25
 */
@Slf4j
@Component
public class OAuthServerAuthenticationEntryPoint implements AuthenticationEntryPoint
{
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws
			IOException
	{
		log.error("Unauthorized request: {}", authException.getMessage(), authException);

		if (authException instanceof ResponseException responseException)
		{
			response.setStatus(responseException.getHttpStatus().value());
			response.setContentType("application/json");

			var dto = ErrorResponseDto.builder().error(responseException.getMessage()).build();

			response.getWriter().write(new ObjectMapper().writeValueAsString(dto));

			return;
		}

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
		response.getWriter().write("{\"error\": \"Unauthorized: " + authException.getMessage() + "\"}");
	}
}
