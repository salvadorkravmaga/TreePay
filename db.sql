CREATE TABLE IF NOT EXISTS accounts (
        identifier text NOT NULL,
	private_key_hex text NOT NULL,
	public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fake_account (
	fakeidentifier text NOT NULL,
	fake_private_key_hex text NOT NULL,
	fake_public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fakeAccounts (
	identifier text NOT NULL,
	EncryptionKey text NOT NULL,
	time_generated text NOT NULL,
	hash text DEFAULT 'None',
	proof_of_work text DEFAULT 'None',
	proof_of_work_time text DEFAULT '0'
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS keys (
	identifier text NOT NULL,
        public_key text NOT NULL,
	private_key text NOT NULL,
	time_generated text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS users (
	identifier text NOT NULL,
        EncryptionKey text NOT NULL,
	time_generated text NOT NULL,
	encryption text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS peers (
        peer text NOT NULL,
	identifier text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS test_peers (
        peer text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS requests (
	type text NOT NULL,
	identifier text NOT NULL,
	ticker text NOT NULL,
	address text DEFAULT 'None',
	amount text DEFAULT 'None',
	time_generated text DEFAULT 'None',
	transaction_on_success text DEFAULT 'None',
	unique_id text NOT NULL,
	transaction_id text NOT NULL,
	transaction_id_times text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS addresses (
	type text NOT NULL,
	identifier text NOT NULL,
	ticker text NOT NULL,
	address text NOT NULL,
	amount text DEFAULT 'None',
	time_generated text NOT NULL,
	paid text DEFAULT 'None',
	transaction_on_success text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS items (
	title text NOT NULL,
	price text NOT NULL,
	transaction_id text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS automated_response (
	purchase_response text NOT NULL,
	donation_response text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS messages (
	type text NOT NULL,
	sender text NOT NULL,
	address text DEFAULT 'None',
	times text NOT NULL,
	refers_to text NOT NULL,
	unique_id text DEFAULT 'None',
	transaction_on_success text DEFAULT 'None',
	time_generated text NOT NULL,
	message text DEFAULT 'None'
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS prices (
	btc_price text NOT NULL,
	ltc_price text NOT NULL
);
