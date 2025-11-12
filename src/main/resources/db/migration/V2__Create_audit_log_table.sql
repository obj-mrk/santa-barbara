CREATE TABLE audit_log (
                           id SERIAL PRIMARY KEY,
                           created_at TIMESTAMPTZ DEFAULT NOW(),  -- Автоматическая установка времени
                           event TEXT NOT NULL,
                           detail TEXT
);

-- Индексы
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_event ON audit_log(event);

-- Комментарии
COMMENT ON TABLE audit_log IS 'Таблица для записи событий Certificate Authority (CA)';
COMMENT ON COLUMN audit_log.created_at IS 'Дата и время создания записи';
COMMENT ON COLUMN audit_log.event IS 'Тип события';
COMMENT ON COLUMN audit_log.detail IS 'Дополнительная информация о событии';