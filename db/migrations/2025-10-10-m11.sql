-- One-success-per (merchant_id, idem_key) in merchant_issue_audit
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='ux_mia_success_once'
  ) THEN
    CREATE UNIQUE INDEX ux_mia_success_once
      ON merchant_issue_audit (merchant_id, idem_key)
      WHERE status_code = 200;
  END IF;
END$$;

-- Redeem receipts (idempotent)
CREATE TABLE IF NOT EXISTS merchant_redeem_receipts (
  merchant_id   text NOT NULL,
  idem_key      text NOT NULL,
  code          text NOT NULL,
  redeemed_at   timestamptz NOT NULL,
  response_json jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (merchant_id, idem_key)
);
CREATE INDEX IF NOT EXISTS idx_mrr_code ON merchant_redeem_receipts(code);

-- Lookup speed
CREATE INDEX IF NOT EXISTS idx_voucher_codes_code_state ON voucher_codes(code, state);
