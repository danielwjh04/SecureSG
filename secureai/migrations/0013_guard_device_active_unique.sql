-- At most one ACTIVE guard device credential per (user, device, integration).
-- Revoked rows stay unconstrained so rotation history is preserved.
CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_devices_active_unique
  ON guard_device_credentials (user_id, device_id, integration)
  WHERE status = 'active';
