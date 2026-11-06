-- Remove only the row this migration seeded; a mode set through the configs API stays.
DELETE FROM configs WHERE key = 'payment_callback' AND config = '{"mode":"legacy"}';
