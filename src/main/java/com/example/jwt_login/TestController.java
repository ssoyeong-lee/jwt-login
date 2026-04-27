package com.example.jwt_login;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class TestController {
	@GetMapping("/")
	public Map home() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		return Map.of(
			"class", auth.getClass(),
			"principal", auth.getPrincipal(),
			"authorities", auth.getAuthorities()
		);

	}

	@PutMapping
	public String putHome() {
		return "hello";
	}
}
