CREATE TABLE auth_sessions (
                               id UUID PRIMARY KEY,
                               user_id UUID NOT NULL,
                               status VARCHAR(32) NOT NULL,
                               created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                               updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                               expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                               consumed BOOLEAN NOT NULL DEFAULT FALSE,
                               CONSTRAINT fk_auth_sessions_user
                                   FOREIGN KEY (user_id) REFERENCES users (id)
);
