package com.example.jwt_login;

import java.time.Duration;
import java.util.NoSuchElementException;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
	private final RedisTemplate<String, String> redisTemplate;
	private static final String KEY_PREFIX = "refresh:user";
	private static final long timeout = TokenType.REFRESH.getExpiration();

	public void save(String username, String value) {
		String key = generateKey(username);
		redisTemplate.opsForValue()
			.set(key, value, Duration.ofSeconds(timeout));
	}

	public void delete(String username) {
		String key = generateKey(username);
		if (redisTemplate.hasKey(key)) {
			redisTemplate.delete(key);
		}
	}

	public String findByUsername(String username) {
		String key = generateKey(username);
		String refresh = redisTemplate.opsForValue().get(key);
		if (refresh == null) {
			throw new NoSuchElementException(key + " 없음");
		}
		return refresh;
	}

	private String generateKey(String username) {
		return KEY_PREFIX + ":" + username;
	}
}
