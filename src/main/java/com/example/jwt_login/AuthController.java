package com.example.jwt_login;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
	private final JwtProvider jwtProvider;
	private final RefreshTokenService refreshTokenService;

	@GetMapping("/refresh")
	String refreshAccessToken(@CookieValue String refresh) {
		jwtProvider.validateJwt(refresh);
		String username = jwtProvider.getUsername(refresh);
		String dbRefresh = refreshTokenService.findByUsername(username);
		if (!refresh.equals(dbRefresh))
			throw new RuntimeException("디비에 저장된 refresh와 일치하지 않음");
		return jwtProvider.createJwt(TokenType.REFRESH, username);
	}
}
