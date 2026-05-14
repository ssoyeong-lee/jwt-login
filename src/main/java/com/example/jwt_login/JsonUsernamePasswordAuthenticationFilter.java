package com.example.jwt_login;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import tools.jackson.databind.ObjectMapper;

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final ObjectMapper objectMapper;

	public JsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		if (!request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		LoginDto loginDto = null;
		try {
			loginDto = objectMapper.readValue(request.getReader(), LoginDto.class);
		} catch (IOException e) {
			throw new InternalAuthenticationServiceException("로그인 인증 시 IOException 발생", e);
		}
		String username = loginDto.getUsername();
		String password = loginDto.getPassword();

		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
		setDetails(request, authRequest);
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	@Data
	private static class LoginDto {
		private String username;
		private String password;
	}
}
