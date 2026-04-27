package com.example.jwt_login;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
	private final JwtProvider jwtProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		String jwt = JwtProvider.extractJwt(request.getHeader("Authorization"));
		if (jwt == null) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			jwtProvider.validateJwt(jwt);
		} catch (JwtException je) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, je.getMessage());
			return;
		}

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
				new User(jwtProvider.getUsername(jwt), null, List.of()),
				null,
				Collections.emptyList());
			SecurityContextHolder.getContext().setAuthentication(authenticated);
		}

		filterChain.doFilter(request, response);
	}
}
