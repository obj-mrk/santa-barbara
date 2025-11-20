package mrk.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Сущность для хранения одноразовых кодов подтверждения (OTP) по email
 * Используется для аутентификации и верификации пользователей
 * Каждая запись представляет собой попытку отправки кода
 *
 * @Table email_otp - таблица для хранения OTP кодов
 */
@Entity
@Table(name = "email_otp")
@Getter
@Setter
public class EmailOtp {

    /**
     * Уникальный идентификатор OTP записи
     * Совпадает с идентификатором сессии аутентификации
     */
    @Id
    @Column(nullable = false)
    private UUID id;

    /**
     * Идентификатор сессии аутентификации
     * Связывает несколько OTP попыток с одной сессией
     */
    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    /**
     * Email адрес, на который отправлен код
     * Должен соответствовать стандартам email адресов
     */
    @Column(nullable = false, length = 320)
    private String email;

    /**
     * Хэш одноразового кода
     * Хранится в зашифрованном виде для безопасности
     */
    @Column(name = "code_hash", nullable = false, length = 255)
    private String codeHash;

    /**
     * Дата и время создания OTP кода
     */
    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    /**
     * Дата и время истечения срока действия кода
     * После этой даты код становится недействительным
     */
    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    /**
     * Количество попыток ввода кода
     * Инкрементируется при каждой неудачной попытке верификации
     */
    @Column(nullable = false)
    private int attempts;

    /**
     * Дата и время последней отправки кода
     * Используется для контроля частоты отправки кодов
     */
    @Column(name = "last_sent_at", nullable = false)
    private OffsetDateTime lastSentAt;

    /**
     * Флаг использования кода
     * true - код был использован для успешной аутентификации
     * false - код еще активен и может быть использован
     */
    @Column(nullable = false)
    private boolean consumed;
}