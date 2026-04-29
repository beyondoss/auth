ALTER TABLE auth.app_config
    ADD COLUMN IF NOT EXISTS session_idle_timeout_seconds int NULL;
