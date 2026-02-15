package mrk.security.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TotpService {
    private final TimeBasedOneTimePasswordGenerator totpGenerator;
    private final Base32 base32;

    /**
     * Генерация нового TOTP-секрета в Base32-представлении.
     * Подходит для хранения в БД и передачи в otpauth:// URL.
     */
    public String generateSecret() {
        try {
            // Алгоритм должен совпадать с тем, что использует totpGenerator (обычно HmacSHA1)
            KeyGenerator keyGenerator = KeyGenerator.getInstance(totpGenerator.getAlgorithm());

            // 160 бит (20 байт) — классический размер ключа для HmacSHA1
            keyGenerator.init(160);

            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretBytes = secretKey.getEncoded();

            // Base32 без '=' padding, в верхнем регистре — типичный формат для otpauth
            return base32.encodeToString(secretBytes)
                    .replace("=", "")
                    .toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ошибка генерации TOTP-секрета", e);
        }
    }

    /**
     * Формирование otpauth:// URL, который фронт закодирует в QR-код.
     * Этот QR сканируется Яндекс.Ключом.
     */
    public String buildOtpAuthUrl(String secret, String accountName, String issuer) {
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(accountName);

        // Обрати внимание: algorithm в otpauth обычно указывается без "Hmac" (SHA1, SHA256 и т.п.)
        String algo = totpGenerator.getAlgorithm().replace("Hmac", "");

        int digits = totpGenerator.getPasswordLength();
        long period = totpGenerator.getTimeStep().getSeconds();

        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
                encodedIssuer,
                encodedAccount,
                secret,
                encodedIssuer,
                algo,
                digits,
                period
        );
    }

    /**
     * Проверка кода TOTP, введенного пользователем.
     * secret — это строка Base32 из БД, code — строка 6 цифр.
     */
    public boolean verifyCode(String secret, String code) throws InvalidKeyException {
        SecretKey secretKey = decodeSecret(secret);

        // Нормализуем код (уберём пробелы и проверим, что только цифры).
        String normalizedCode = code.trim();
        if (!normalizedCode.matches("\\d+")) {
            return false;
        }

        // Небольшое временное окно: текущий шаг и по одному шагу до/после.
        // Это повышает устойчивость к рассинхронизации времени.
        int window = 1;
        Instant now = Instant.now();
        Duration timeStep = totpGenerator.getTimeStep();

        for (int i = -window; i <= window; i++) {
            Instant instant = now.plus(timeStep.multipliedBy(i));

            int otp = totpGenerator.generateOneTimePassword(secretKey, instant);
            String expectedCode = String.format("%0" + totpGenerator.getPasswordLength() + "d", otp);

            if (expectedCode.equals(normalizedCode)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Вспомогательный метод: преобразовать Base32-строку секрета в SecretKey.
     */
    private SecretKey decodeSecret(String secret) {
        // Восстанавливаем padding, если ты его срезал при генерации
        String normalizedSecret = secret.replace(" ", "").toUpperCase();
        byte[] keyBytes = base32.decode(normalizedSecret);

        return new SecretKeySpec(keyBytes, totpGenerator.getAlgorithm());
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
