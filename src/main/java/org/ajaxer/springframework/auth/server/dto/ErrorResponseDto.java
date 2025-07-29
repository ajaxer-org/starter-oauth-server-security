package org.ajaxer.springframework.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

/**
 * @author Shakir Ansari
 * @since 2025-07-04
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponseDto
{
	private String error;
	private String description;
	private String errorCode;
	private String uri;
}
