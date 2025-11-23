package mrk.security.admin.dto;

import mrk.persistence.entity.enums.UserRole;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO с информацией о пользователе для административных операций
 */
public record AdminUserResponse(
        UUID id,
        String email,
        String name,
        UserRole role,
        boolean emailVerified,
        boolean blocked,
        Instant createdAt
) {}
