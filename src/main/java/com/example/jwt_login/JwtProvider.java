package com.example.jwt_login;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.apache.el.parser.Token;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtProvider {
	private final SecretKey key;
	private final JwtParser jwtParser;
	private final String issuer = "JWT Login Project";

	public JwtProvider(@Value("${spring.jwt.secret-key}") String secretKey) {
		this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
		this.jwtParser = Jwts.parser().verifyWith(key).requireIssuer(issuer).build();
	}

	public String createJwt(TokenType tokenType, String username) {
		return Jwts.builder()
			.header()
			.add("tokenType", tokenType)
			.and()
			.claim("username", username)
			.issuer(issuer)
			.issuedAt(new Date())
			.expiration(new Date(System.currentTimeMillis() + tokenType.getExpiration() * 1000L))
			.signWith(key)
			.compact();
	}

	public void validateJwt(String jwt) {
		Claims payload = jwtParser.parseSignedClaims(jwt)
			.getPayload();

		if (payload.getExpiration() != null && payload.getExpiration().before(new Date())) {
			throw new JwtException("토큰 유효기간 만료");
		}

		if (payload.getIssuedAt() != null && payload.getIssuedAt().after(new Date())) {
			throw new JwtException("해당 토큰의 발급 시점이 미래");
		}
	}

	public String getUsername(String jwt) {
		return jwtParser.parseSignedClaims(jwt)
			.getPayload()
			.get("username", String.class);
	}

	public static String extractJwt(String authorizationHeader) {
		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
			return null;
		}
		return authorizationHeader.substring("Bearer ".length());
	}
}
