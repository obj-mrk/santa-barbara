package mrk.persistence.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import mrk.persistence.entity.enums.UserRole;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Сущность пользователя системы
 * Хранит основную информацию о пользователе и его учетные данные
 *
 * @Table users - соответствует таблице пользователей в базе данных
 */
@Entity
@Table(name = "users")
@Getter
@Setter
public class User {

    /**
     * Уникальный идентификатор пользователя
     * Генерируется автоматически при создании
     */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    /**
     * Email пользователя (используется для входа в систему)
     * Должен быть уникальным и обязательным для заполнения
     */
    @Column(nullable = false, unique = true, length = 100)
    private String email;

    /**
     * Флаг подтверждения email адреса
     * false - email не подтвержден, true - email подтвержден
     */
    @Column(nullable = false)
    private boolean emailVerified = false;

    /**
     * Хэш пароля пользователя
     * Хранится в зашифрованном виде, обязателен для заполнения
     */
    @Column(nullable = false, length = 255)
    @NotBlank
    private String password;

    /**
     * Отображаемое имя пользователя
     * Используется для персонализации интерфейса
     */
    @Column(length = 100)
    @NotBlank
    private String name;

    /**
     * Роль пользователя в системе
     * Определяет уровень доступа и права
     * По умолчанию устанавливается USER
     */
    @Enumerated(EnumType.STRING)
    @Column(length = 20, nullable = false)
    private UserRole role = UserRole.USER;

    /**
     * Дата и время создания учетной записи
     * Устанавливается автоматически при создании и не изменяется
     */
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;
}