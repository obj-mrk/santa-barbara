package mrk.security.otp;

import lombok.RequiredArgsConstructor;
import mrk.security.service.EmailSenderService;
import mrk.persistence.entity.EmailOtp;
import mrk.persistence.repo.EmailOtpRepository;
import mrk.security.config.EmailOtpProperties;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Уникальный идентификатор записи OTP. Не совпадает с sessionId; связь с сессией хранится в поле sessionId.
 */

@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private final EmailOtpRepository otpRepository;
    private final EmailOtpProperties properties;
    private final EmailSenderService emailSender;
    private final PasswordEncoder passwordEncoder;

    // Генератор криптографически безопасных случайных чисел для создания OTP кодов
    private final SecureRandom random = new SecureRandom();

    /**
     * Создает и отправляет одноразовый код подтверждения на указанный email
     * Проверяет ограничение на частоту повторных отправок перед созданием нового кода
     *
     * @param sessionId уникальный идентификатор сессии аутентификации
     * @param email адрес электронной почты для отправки кода
     * @throws IllegalStateException если превышен лимит частоты повторных отправок
     */
    @Transactional
    public void createAndSendOtp(UUID sessionId, String email) {
        OffsetDateTime now = OffsetDateTime.now();

        // Поиск активного (не использованного) OTP для данной сессии
        Optional<EmailOtp> existing = otpRepository
                .findTopBySessionIdAndConsumedFalseOrderByCreatedAtDesc(sessionId);

        // Проверка ограничения на частоту повторных отправок
        if (existing.isPresent()) {
            EmailOtp otp = existing.get();
            if (otp.getLastSentAt().plusSeconds(properties.getResendCooldownSeconds())
                    .isAfter(now)) {
                throw new IllegalStateException("Слишком частая отправка OTP");
            }
        }

        // Генерация и хэширование OTP кода
        String code = generateCode();
        String codeHash = passwordEncoder.encode(code);

        // Создание новой сущности OTP
        EmailOtp otp = new EmailOtp();
        otp.setId(UUID.randomUUID());
        otp.setSessionId(sessionId);
        otp.setEmail(email);
        otp.setCodeHash(codeHash);
        otp.setCreatedAt(now);
        otp.setExpiresAt(now.plusMinutes(properties.getTtlMinutes()));
        otp.setAttempts(0);
        otp.setLastSentAt(now);
        otp.setConsumed(false);

        otpRepository.save(otp);

        // Отправка кода пользователю (оригинальный код, не хэш)
        emailSender.sendOtpCode(email, code);
    }

    /**
     * Проверяет валидность введенного OTP кода
     * Выполняет комплексную проверку: использование, срок действия, лимит попыток, корректность кода
     *
     * @param sessionId идентификатор сессии
     * @param code введенный пользователем код
     * @return email пользователя при успешной проверке
     * @throws IllegalStateException если код использован, истек или превышены попытки
     * @throws IllegalArgumentException если код не найден или неверен
     */

    @Transactional
    public String verifyOtp(UUID sessionId, String code) {
        OffsetDateTime now = OffsetDateTime.now();

        // Поиск активного OTP для сессии
        EmailOtp otp = otpRepository.findTopBySessionIdAndConsumedFalseOrderByCreatedAtDesc(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Код не найден или уже использован"));

        if (otp.isConsumed()) {
            throw new IllegalStateException("Код уже был использован");
        }

        if (otp.getExpiresAt().isBefore(now)) {
            throw new IllegalStateException("Срок действия кода истёк");
        }

        if (otp.getAttempts() >= properties.getMaxAttempts()) {
            throw new IllegalStateException("Превышено количество попыток ввода кода");
        }

        // увеличиваем счётчик попыток независимо от результата
        otp.setAttempts(otp.getAttempts() + 1);

        // Проверка соответствия введенного кода хэшу в базе данных
        if (!passwordEncoder.matches(code, otp.getCodeHash())) {
            otpRepository.save(otp);
            throw new IllegalArgumentException("Неверный код");
        }

        // успешная проверка
        otp.setConsumed(true);
        otpRepository.save(otp);

        return otp.getEmail();
    }

    private String generateCode() {
        // 6-значный код с ведущими нулями
        int num = random.nextInt(1_000_000);
        return String.format("%06d", num);
    }
}
