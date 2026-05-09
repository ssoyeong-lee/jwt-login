package com.example.jwt_login;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum TokenType {
	ACCESS(1 * 60), REFRESH(5 * 60);

	private final int expiration;
}
