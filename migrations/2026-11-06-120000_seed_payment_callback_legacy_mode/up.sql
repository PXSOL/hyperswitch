-- PXSOL fork: the router refuses to start without a `payment_callback` config row (upstream
-- #15144, `PaymentCallbackConfig::validate_at_startup`). Seed the legacy mode, which keeps the
-- callback URLs the connectors use today (no single-use tokens). A value already set through
-- the configs API is kept.
INSERT INTO configs (key, config)
VALUES ('payment_callback', '{"mode":"legacy"}')
ON CONFLICT (key) DO NOTHING;
