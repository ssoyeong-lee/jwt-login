package com.example.jwt_login;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {
	private final JwtProvider jwtProvider;
	private final RefreshTokenService refreshTokenService;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response,
		@Nullable Authentication authentication) {
		String jwt = JwtProvider.extractJwt(request.getHeader("Authorization"));
		refreshTokenService.delete(jwtProvider.getUsername(jwt));

		Cookie cookie = new Cookie("refresh", "");
		cookie.setMaxAge(0);
		response.addCookie(cookie);
	}
}
