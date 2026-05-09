package com.example.jwt_login;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
	private final JwtProvider jwtProvider;

	public SecurityConfig(JwtProvider jwtProvider) {
		this.jwtProvider = jwtProvider;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		return http
			.csrf(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.formLogin(form -> form
				.successHandler(authenticationSuccessHandler()))
			.authorizeHttpRequests(request -> request
				.requestMatchers("/login", "/error/**", "/auth/refresh").permitAll()
				.anyRequest().authenticated()
			)
			.cors(cors -> cors
				.configurationSource(apiConfigurationSource()))
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
			.exceptionHandling(eh -> eh
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
			.build();
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
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new JwtSuccessHandler(jwtProvider);
	}

	UrlBasedCorsConfigurationSource apiConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("http://localhost:63342")); //포트 변경??
		configuration.setAllowedMethods(List.of("GET", "POST"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(List.of("Authorization"));
		configuration.setExposedHeaders(List.of("Authorization"));//설정 안하면 브라우저에서 노출 안 시킴
		configuration.setMaxAge(Duration.ofHours(2)); //최대 2시간 가능 크로미움에서

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
