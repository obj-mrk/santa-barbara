package mrk.security.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record Totp3faRequest(
        @NotNull UUID sessionId,
        @NotBlank String code
) { }
