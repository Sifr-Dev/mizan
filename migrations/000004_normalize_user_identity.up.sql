-- Canonicalize user identity before enforcing database-level invariants.
-- The preflight deliberately fails instead of guessing which duplicate account
-- should survive. An operator must resolve those rows before retrying.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM users
        GROUP BY LOWER(BTRIM(email))
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot normalize users.email: duplicate canonical addresses exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM users
        WHERE role IS NULL OR (BTRIM(role) <> '' AND BTRIM(role) NOT IN ('user', 'admin'))
    ) THEN
        RAISE EXCEPTION 'cannot normalize users.role: unsupported role value exists';
    END IF;
END
$$;

UPDATE users
SET email = LOWER(BTRIM(email)),
    updated_at = NOW()
WHERE email <> LOWER(BTRIM(email));

UPDATE users
SET role = 'user',
    updated_at = NOW()
WHERE role IS NULL OR BTRIM(role) = '';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users
    ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));

-- The application and database now use the same canonical email key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_canonical
    ON users (LOWER(BTRIM(email)));
