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

	@GetMapping("/refresh")
	String refreshAccessToken(@CookieValue String refresh) {
		jwtProvider.validateJwt(refresh);
		return jwtProvider.createJwt(TokenType.REFRESH, "test");
	}
}
