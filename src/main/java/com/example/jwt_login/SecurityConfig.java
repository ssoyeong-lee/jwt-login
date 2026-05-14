package com.example.jwt_login;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import tools.jackson.databind.ObjectMapper;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
	private final JwtProvider jwtProvider;
	private final RefreshTokenService refreshTokenService;
	private final ObjectMapper objectMapper;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordAuthenticationFilter =
			new JsonUsernamePasswordAuthenticationFilter(objectMapper);

		DefaultSecurityFilterChain defaultSecurityFilterChain = http
			.addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
			.addFilterAt(jsonUsernamePasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.csrf(AbstractHttpConfigurer::disable)
			.cors(cors -> cors
				.configurationSource(apiConfigurationSource()))
			.logout(logout -> logout
				.addLogoutHandler(jwtLogoutHandler())
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
			)
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.exceptionHandling(eh -> eh
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
			.authorizeHttpRequests(request -> request
				.requestMatchers("/login", "/error/**", "/auth/refresh").permitAll()
				.anyRequest().authenticated()
			)
			.build();

		jsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(
			http.getSharedObject(AuthenticationManager.class)
		);
		jsonUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
		return defaultSecurityFilterChain;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
			User.withUsername("user")
				.password("{noop}1234")
				.roles("USER")
				.build()
		);
	}

	@Bean
	public LogoutHandler jwtLogoutHandler() {
		return new JwtLogoutHandler(jwtProvider, refreshTokenService);
	}
	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new JwtSuccessHandler(jwtProvider, refreshTokenService);
	}

	private UrlBasedCorsConfigurationSource apiConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("http://localhost:63342")); //포트 변경??
		configuration.setAllowedMethods(List.of("GET", "POST"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
		configuration.setExposedHeaders(List.of("Authorization"));//설정 안하면 브라우저에서 노출 안 시킴
		configuration.setMaxAge(Duration.ofHours(2)); //최대 2시간 가능 크로미움에서

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
