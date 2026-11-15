-- Email and role values were normalized in the forward migration and cannot
-- be reconstructed safely. This rollback removes only the added constraints.
DROP INDEX IF EXISTS idx_users_email_canonical;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_role_check;
