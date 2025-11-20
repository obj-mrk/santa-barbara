package mrk.security.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record OtpVerifyRequest(@NotNull UUID sessionId,
                               @NotBlank String code) {
}
