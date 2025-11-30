package mrk.persistence.entity.enums;

public enum AuthSessionStatus {
    PASSWORD_VERIFIED,   // пароль пройден, ждём e-mail OTP
    EMAIL_VERIFIED,      // e-mail OTP пройден, ждём TOTP
    COMPLETED,           // все факторы пройдены, JWT уже выдан
    EXPIRED,             // истекло по времени
    CANCELLED            // принудительно завершено (опционально)
}
