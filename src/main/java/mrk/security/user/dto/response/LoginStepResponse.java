package mrk.security.user.dto.response;

import java.util.UUID;

public record LoginStepResponse(UUID session,
                                String nextFactor) {
}
