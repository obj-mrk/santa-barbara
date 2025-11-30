package mrk.security.totp;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import mrk.security.service.UserTotpService;
import mrk.security.user.dto.request.TotpVerifyRequest;
import mrk.security.user.dto.response.TotpSetupResponse;
import mrk.security.user.dto.response.TotpStatusResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;

/**
 * Контроллер для управления TOTP (Яндекс.Ключ) текущего пользователя:
 * - подключение;
 * - подтверждение;
 * - отключение;
 * - получение статуса.
 */
@RestController
@RequestMapping("/api/v1/auth/totp")
@RequiredArgsConstructor
public class TotpController {

    private final UserTotpService userTotpService;

    /**
     * Инициализация TOTP:
     * генерирует секрет, сохраняет в БД и возвращает otpauth:// URL для QR.
     *
     * Доступен только для аутентифицированного пользователя (JWT).
     */
    @PostMapping("/setup")
    public ResponseEntity<TotpSetupResponse> setup() {
        TotpSetupResponse response = userTotpService.setupTotp();
        return ResponseEntity.ok(response);
    }

    /**
     * Подтверждение TOTP-кода и окончательное включение TOTP.
     */
    @PostMapping("/confirm")
    public ResponseEntity<Void> confirm(@Valid @RequestBody TotpVerifyRequest request) throws InvalidKeyException {
        userTotpService.confirmTotp(request.code());
        return ResponseEntity.ok().build();
    }

    /**
     * Отключение TOTP.
     */
    @PostMapping("/disable")
    public ResponseEntity<Void> disable() {
        userTotpService.disableTotp();
        return ResponseEntity.ok().build();
    }

    /**
     * Получение статуса TOTP (включен / выключен).
     */
    @GetMapping("/status")
    public ResponseEntity<TotpStatusResponse> status() {
        TotpStatusResponse response = userTotpService.getStatus();
        return ResponseEntity.ok(response);
    }
}
