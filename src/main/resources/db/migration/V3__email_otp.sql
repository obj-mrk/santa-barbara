CREATE TABLE email_otp (
                           id UUID PRIMARY KEY,
                           session_id UUID NOT NULL,
                           email VARCHAR(320) NOT NULL,
                           code_hash VARCHAR(255) NOT NULL,
                           created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                           expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                           attempts INT NOT NULL DEFAULT 0,
                           last_sent_at TIMESTAMP WITH TIME ZONE NOT NULL,
                           consumed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_email_otp_session_active
    ON email_otp(session_id)
    WHERE consumed = FALSE;