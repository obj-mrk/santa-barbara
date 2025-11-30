package mrk.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import mrk.persistence.entity.enums.AuthSessionStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * Сессия аутентификации с несколькими факторами (3FA).
 * Связывает пользователя, состояние прохождения факторов и срок жизни сессии.
 */
@Entity
@Table(name = "auth_sessions")
@Getter
@Setter
public class AuthSession {

    @Id
    @GeneratedValue
    private UUID id;

    /**
     * Пользователь, для которого выполняется аутентификация.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    /**
     * Текущий статус прохождения факторов.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AuthSessionStatus status;

    /**
     * Момент создания сессии.
     */
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Момент, после которого сессию нельзя использовать.
     */
    @Column(nullable = false)
    private Instant expiresAt;

    /**
     * Флаг, что сессия уже использована для выдачи финального JWT
     * и не может быть повторно задействована.
     */
    @Column(nullable = false)
    private boolean consumed = false;

    /**
     * Последнее время обновления статуса (для аудита/аналитики).
     */
    @Column(nullable = false)
    private Instant updatedAt;

    // геттеры/сеттеры + удобные методы-доменные операции

    @PrePersist
    public void prePersist() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }

    /**
     * Проверка, что сессия ещё действительна.
     */
    public boolean isActive() {
        return !consumed
                && status != AuthSessionStatus.EXPIRED
                && Instant.now().isBefore(expiresAt);
    }

    /**
     * Переводит сессию в статус истечения.
     */
    public void markExpired() {
        this.status = AuthSessionStatus.EXPIRED;
        this.consumed = true;
    }

    /**
     * Помечает сессию как успешно завершённую.
     */
    public void markCompleted() {
        this.status = AuthSessionStatus.COMPLETED;
        this.consumed = true;
    }
}
