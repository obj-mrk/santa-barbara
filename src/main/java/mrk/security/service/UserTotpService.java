package mrk.security.service;

import lombok.RequiredArgsConstructor;
import mrk.persistence.entity.User;
import mrk.persistence.repo.UserRepository;
import mrk.security.user.dto.response.TotpSetupResponse;
import mrk.security.user.dto.response.TotpStatusResponse;
import mrk.security.user.CustomUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.InvalidKeyException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class UserTotpService {

    private final UserRepository userRepository;
    private final TotpService totpService;

    /**
     * Инициализация TOTP для текущего пользователя:
     * - генерируется новый секрет;
     * - сохраняется в БД;
     * - возвращается otpauth:// URL для генерации QR-кода.
     */
    public TotpSetupResponse setupTotp() {
        User user = getCurrentUser();

        // Если уже включено — решай сам: либо кидать исключение, либо разрешать переинициализацию
        if (user.isTotpEnabled()) {
            throw new IllegalStateException("TOTP уже включен для данного пользователя");
        }

        String secret = totpService.generateSecret();
        user.setTotpSecret(secret);
        user.setTotpEnabled(false); // включим только после успешного подтверждения кода

        userRepository.save(user);

        String otpauthUrl = totpService.buildOtpAuthUrl(
                secret,
                user.getEmail(),
                "SantaBarbara"    // issuer — латинкой, имя твоего сервиса
        );

        return new TotpSetupResponse(secret, otpauthUrl);
    }

    /**
     * Подтверждение кода из Яндекс.Ключ и окончательное включение TOTP.
     */
    public void confirmTotp(String code) throws InvalidKeyException {
        User user = getCurrentUser();

        if (user.getTotpSecret() == null) {
            throw new IllegalStateException("TOTP секрет не инициализирован для пользователя");
        }

        boolean ok = totpService.verifyCode(user.getTotpSecret(), code);
        if (!ok) {
            // тут можно прикрутить счётчик попыток, блокировки и т.п.
            throw new IllegalArgumentException("Неверный TOTP код");
        }

        user.setTotpEnabled(true);
        userRepository.save(user);
    }

    /**
     * Отключение TOTP для пользователя.
     * Можно хранить секрет, а можно его очищать.
     */
    public void disableTotp() {
        User user = getCurrentUser();

        user.setTotpEnabled(false);
        user.setTotpSecret(null); // опционально — "забываем" секрет
        userRepository.save(user);
    }

    /**
     * Статус TOTP (включен/выключен) для текущего пользователя.
     */
    @Transactional(readOnly = true)
    public TotpStatusResponse getStatus() {
        User user = getCurrentUser();
        return new TotpStatusResponse(user.isTotpEnabled());
    }

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof CustomUserDetails cud)) {
            throw new IllegalStateException("Не удалось определить текущего пользователя");
        }

        UUID userId = cud.getId();
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("Пользователь не найден"));
    }
}
