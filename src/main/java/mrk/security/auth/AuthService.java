package mrk.security.auth;

import lombok.RequiredArgsConstructor;

import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.UserRole;
import mrk.persistence.repo.UserRepository;
import mrk.security.jwt.JwtService;
import mrk.security.otp.EmailOtpService;
import mrk.security.user.CustomUserDetails;
import mrk.security.user.dto.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Сервис аутентификации и регистрации пользователей
 * Обрабатывает бизнес-логику связанную с управлением доступом
 *
 * @Transactional - все методы выполняются в транзакциях для обеспечения
 * целостности данных и избежания частичных обновлений
 */

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailOtpService emailOtpService;

    /**
     * Регистрация нового пользователя в системе
     * Создает учетную запись, хэширует пароль и выдает JWT токен
     *
     * @param request DTO с данными для регистрации
     * @return AuthResponse с JWT токеном доступа
     * @throws IllegalArgumentException если email уже зарегистрирован
     */

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Проверка уникальности email в системе
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // Создание и настройка нового пользователя
        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setName(request.name());
        user.setRole(UserRole.USER);
        userRepository.save(user);

        // Генерация JWT токена на основе данных пользователя
        String token = jwtService.generateToken(CustomUserDetails.fromUser(user));

        return new AuthResponse(token);
    }

    /**
     * Первый этап аутентификации пользователя
     * Проверяет email и пароль, инициирует отправку OTP кода
     *
     * @param request DTO с учетными данными
     * @return LoginStep1Response с sessionId для OTP верификации
     */
    @Transactional
    public LoginStep1Response login(LoginRequest request) {
        // Аутентификация пользователя через Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(),
                        request.password()
                )
        );
        // Получение аутентифицированных данных пользователя
        CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();
        String email = principal.getUsername();

        // Генерация уникального идентификатора сессии
        UUID sessionId = UUID.randomUUID();

        // Создание и отправка OTP кода на email пользователя
        emailOtpService.createAndSendOtp(sessionId, email);

        return new LoginStep1Response(sessionId, "EMAIL_OTP");
    }

    /**
     * Второй этап аутентификации - верификация OTP кода
     * Подтверждает код и выдает финальный JWT токен
     *
     * @param request DTO с sessionId и OTP кодом
     * @return AuthResponse с JWT токеном доступа
     * @throws IllegalStateException если пользователь не найден
     */
    @Transactional
    public AuthResponse verifyOtpAndIssueToken(OtpVerifyRequest request) {
        // Верификация OTP кода и получение email пользователя
        String email = emailOtpService.verifyOtp(request.sessionId(), request.code());

        // Поиск пользователя по email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Пользователь с таким e-mail не найден"));

        // Генерация финального JWT токена
        String token = jwtService.generateToken(CustomUserDetails.fromUser(user));

        return new AuthResponse(token);
    }
}
