package mrk.security.config;

import lombok.RequiredArgsConstructor;
import mrk.security.jwt.JwtAuthenticationFilter;
import mrk.security.user.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Конфигурация безопасности Spring Security
 * Определяет правила доступа, аутентификации и авторизации для приложения
 *
 * @EnableWebSecurity - активирует настройки безопасности веб-приложения
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final CustomUserDetailsService customUserDetailsService;

    /**
     * Основная конфигурация цепочки безопасности HTTP
     * Определяет защищенные endpoints, политики сессий и фильтры
     *
     * @param http объект для настройки безопасности
     * @return сконфигурированная цепочка безопасности
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Отключаем CSRF защиту для REST API (не нужна для stateless аутентификации)
                .csrf(AbstractHttpConfigurer::disable)
                // Устанавливаем политику без сохранения состояния (stateless)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Настройка правил авторизации для различных endpoints
                .authorizeHttpRequests(auth -> auth
                        // публичные — регистрация и вход
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login/password",
                                "/api/v1/auth/login/otp",
                                "/api/v1/auth/login/totp"
                        ).permitAll()
                        // остальные /auth/** только с JWT
                        .requestMatchers("/api/v1/auth/**").authenticated()
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                // Настройка провайдера аутентификации
                .authenticationProvider(authenticationProvider())
                // Добавление JWT фильтра перед стандартным фильтром аутентификации
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * Провайдер аутентификации, связывающий Spring Security с пользовательским сервисом
     * Использует CustomUserDetailsService для загрузки данных пользователя
     *
     * @return настроенный DaoAuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * Кодировщик паролей для безопасного хранения в базе данных
     * Использует алгоритм BCrypt для хэширования
     *
     * @return BCryptPasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Менеджер аутентификации, координирующий процесс проверки учетных данных
     * Используется для аутентификации пользователей через различные провайдеры
     *
     * @param config конфигурация аутентификации
     * @return AuthenticationManager instance
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}