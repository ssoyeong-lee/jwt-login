package com.example.jwt_login;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtSuccessHandler implements AuthenticationSuccessHandler {
	private final JwtProvider jwtProvider;
	private final RefreshTokenService refreshTokenService;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		UserDetails principal = (UserDetails)authentication.getPrincipal();
		response.addHeader("Authorization", "Bearer " + jwtProvider.createJwt(TokenType.ACCESS, principal.getUsername()));
		response.getWriter().println("{\"message\": \"login success\"}");

		String refresh = jwtProvider.createJwt(TokenType.REFRESH, principal.getUsername());
		Cookie cookie = new Cookie("refresh", refresh);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(TokenType.REFRESH.getExpiration());
		cookie.setAttribute("SameSite", "Strict");
		response.addCookie(cookie);

		refreshTokenService.save(principal.getUsername(), refresh);
	}
}
