package mrk.security.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import mrk.security.user.dto.request.*;
import mrk.security.user.dto.response.AuthResponse;
import mrk.security.user.dto.response.LoginStepResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST контроллер для обработки запросов аутентификации и регистрации
 * Предоставляет API endpoints для управления доступом пользователей к системе
 */

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    /**
     * Регистрация нового пользователя в системе
     * Создает учетную запись и возвращает JWT токен для доступа
     *
     * @param registerRequest DTO с данными для регистрации
     * @return AuthResponse с JWT токеном доступа
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authService.register(registerRequest));
    }

    /**
     * Первый этап входа в систему
     * Проверяет учетные данные и инициирует процесс OTP аутентификации
     *
     * @param loginRequest DTO с email и паролем
     * @return LoginStep1Response с sessionId для следующего этапа
     */
    @PostMapping("/login/password")
    public ResponseEntity<LoginStepResponse> login3fa(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login3fa(loginRequest));
    }

    /**
     * Второй этап входа - верификация OTP кода
     * Подтверждает одноразовый код
     *
     * @param request DTO с sessionId и OTP кодом
     * @return AuthResponse с JWT токеном доступа
     */
    @PostMapping("/login/otp")
    public ResponseEntity<LoginStepResponse> verifyEmailOtp3fa(@Valid @RequestBody EmailOtp3faRequest request) {
        return ResponseEntity.ok(authService.verifyEmailOtp3fa(request));
    }

    /**
     * Третий этап входа - верификация TOTP кода
     * Подтверждает одноразовый код
     * Возвращение jwt токена
     */
    @PostMapping("/login/totp")
    public ResponseEntity<AuthResponse> verifyTotp3fa(@Valid @RequestBody Totp3faRequest request) {
        return ResponseEntity.ok(authService.verifyTotp3faAndIssueToken(request));
    }
}
