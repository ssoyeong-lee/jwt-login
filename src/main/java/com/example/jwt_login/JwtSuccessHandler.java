package com.example.jwt_login;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtSuccessHandler implements AuthenticationSuccessHandler {
	private final JwtProvider jwtProvider;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		UserDetails principal = (UserDetails)authentication.getPrincipal();
		response.addHeader("Authorization", "Bearer " + jwtProvider.createJwt(principal.getUsername()));
		response.getWriter().println("{\"message\": \"login success\"}");
	}
}
