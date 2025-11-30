package mrk.exception;

import java.time.Instant;

record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message
) {}
