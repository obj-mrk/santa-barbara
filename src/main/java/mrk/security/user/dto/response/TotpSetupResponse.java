package mrk.security.user.dto.response;

public record TotpSetupResponse(
        String secret,
        String otpauthUrl
) {}
