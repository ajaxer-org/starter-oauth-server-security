package org.ajaxer.springframework.auth.server.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * @author Shakir Ansari
 * @since 2025-07-24
 */
@Getter
@ToString
@Builder
public class JwtHeader
{
	public final String kid;
	public final String alg;
}
