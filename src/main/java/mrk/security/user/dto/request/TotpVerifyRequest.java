package mrk.security.user.dto.request;

import jakarta.validation.constraints.NotBlank;

public record TotpVerifyRequest(
        @NotBlank String code
) {}
