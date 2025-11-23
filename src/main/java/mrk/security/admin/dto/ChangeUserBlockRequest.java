package mrk.security.admin.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Запрос на изменение статуса блокировки учетной записи
 */
public record ChangeUserBlockRequest(
        @NotNull Boolean blocked
) {}
