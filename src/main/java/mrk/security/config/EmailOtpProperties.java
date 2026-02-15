package mrk.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Конфигурационные свойства для настройки OTP (One-Time Password) системы
 * Настраивается через application.properties/yaml с префиксом 'app.email-otp'
 *
 * @ConfigurationProperties - связывает свойства из конфигурационных файлов с полями класса
 */
@Component
@ConfigurationProperties(prefix = "app.email-otp")
@Getter
@Setter
public class EmailOtpProperties {

    /**
     * Время жизни OTP кода в минутах
     * Определяет как долго код остается действительным после отправки
     */
    private int ttlMinutes;

    /**
     * Минимальный интервал между повторными отправками кода (в секундах)
     * Защищает от спама и злоупотреблений
     */
    private int resendCooldownSeconds;

    /**
     * Максимальное количество попыток ввода неверного кода
     * При превышении лимита код становится недействительным
     */
    private int maxAttempts;

    /**
     * Email адрес отправителя для OTP писем
     * Отображается как адрес отправителя в почтовых клиентах
     */
    private String sender;
}