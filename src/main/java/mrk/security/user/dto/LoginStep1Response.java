package mrk.security.user.dto;

import java.util.UUID;

public record LoginStep1Response(UUID session,
                                 String nextFactor) {
}
