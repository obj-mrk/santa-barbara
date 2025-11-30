package mrk.security.auth;

import lombok.RequiredArgsConstructor;

import mrk.persistence.entity.AuthSession;
import mrk.persistence.entity.User;
import mrk.persistence.entity.enums.AuthSessionStatus;
import mrk.persistence.entity.enums.UserRole;
import mrk.persistence.repo.AuthSessionRepository;
import mrk.persistence.repo.UserRepository;
import mrk.security.jwt.JwtService;
import mrk.security.otp.EmailOtpService;
import mrk.security.service.TotpService;
import mrk.security.user.CustomUserDetails;
import mrk.security.user.dto.request.*;
import mrk.security.user.dto.response.AuthResponse;
import mrk.security.user.dto.response.LoginStepResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Сервис аутентификации и регистрации пользователей.
 * Отвечает за:
 *  - регистрацию;
 *  - аутентификацию по паролю + e-mail OTP (двухфакторная схема);
 *  - аутентификацию по паролю + TOTP (двухфакторная схема с Яндекс.Ключом).
 */

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailOtpService emailOtpService;
    private final TotpService totpService;
    private final AuthSessionRepository authSessionRepository;

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
    public LoginStepResponse login3fa(LoginRequest request) {
        // 1) Проверяем логин/пароль через AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(principal.getUsername())
                .orElseThrow(() -> new IllegalStateException("Пользователь не найден"));

        // 2) Создаём AuthSession
        AuthSession session = new AuthSession();
        session.setUser(user);
        session.setStatus(AuthSessionStatus.PASSWORD_VERIFIED);
        session.setExpiresAt(Instant.now().plusSeconds(15 * 60));
        authSessionRepository.save(session);

        // 3) Создаём и отправляем OTP, привязанный к этой сессии
        emailOtpService.createAndSendOtp(session.getId(), user.getEmail());

        // 4) Возвращаем sessionId и следующий фактор
        return new LoginStepResponse(session.getId(), "EMAIL_OTP");
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
    public LoginStepResponse verifyEmailOtp3fa(EmailOtp3faRequest request) {
        AuthSession session = authSessionRepository.findById(request.sessionId())
                .orElseThrow(() -> new IllegalArgumentException("Сессия аутентификации не найдена"));

        if (!session.isActive()) {
            throw new IllegalStateException("Сессия аутентификации недействительна или истекла");
        }

        if (session.getStatus() != AuthSessionStatus.PASSWORD_VERIFIED) {
            throw new IllegalStateException("Неверный этап аутентификации для проверки e-mail OTP");
        }

        // проверяем OTP, привязанный к этой сессии
        emailOtpService.verifyOtp(session.getId(), request.code());

        // переводим сессию на следующий этап
        session.setStatus(AuthSessionStatus.EMAIL_VERIFIED);
        authSessionRepository.save(session);

        // возвращаем sessionId и следующий фактор: TOTP
        return new LoginStepResponse(session.getId(), "TOTP");
    }

    @Transactional
    public AuthResponse verifyTotp3faAndIssueToken(Totp3faRequest request) {
        AuthSession session = authSessionRepository.findById(request.sessionId())
                .orElseThrow(() -> new IllegalArgumentException("Сессия аутентификации не найдена"));

        if (!session.isActive()) {
            throw new IllegalStateException("Сессия аутентификации недействительна или истекла");
        }

        if (session.getStatus() != AuthSessionStatus.EMAIL_VERIFIED) {
            throw new IllegalStateException("Неверный этап аутентификации для проверки TOTP");
        }

        User user = session.getUser();

        if (!user.isTotpEnabled() || user.getTotpSecret() == null) {
            throw new IllegalStateException("Для пользователя не настроена TOTP-аутентификация");
        }

        boolean ok;
        try {
            ok = totpService.verifyCode(user.getTotpSecret(), request.code());
        } catch (Exception e) {
            throw new IllegalStateException("Ошибка проверки TOTP-кода", e);
        }

        if (!ok) {
            throw new IllegalArgumentException("Неверный TOTP-код");
        }

        // Всё успешно: помечаем сессию как завершённую и потреблённую
        session.markCompleted();
        authSessionRepository.save(session);

        // Генерируем финальный JWT
        String token = jwtService.generateToken(CustomUserDetails.fromUser(user));
        return new AuthResponse(token);
    }
}
