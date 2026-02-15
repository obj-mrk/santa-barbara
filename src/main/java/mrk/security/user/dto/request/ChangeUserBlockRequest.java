package mrk.security.user.dto.request;

import jakarta.validation.constraints.NotNull;

/**
 * Запрос на изменение статуса блокировки учетной записи
 */
public record ChangeUserBlockRequest(
        @NotNull Boolean blocked
) {}
