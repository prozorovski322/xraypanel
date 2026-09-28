-- name: GetPKIEntry :one
SELECT * FROM pki WHERE id = $1;

-- InsertPKIEntryIfAbsent creates a PKI entry only when none exists.
--
-- DO NOTHING rather than an upsert: overwriting the certificate authority would
-- invalidate every node certificate at once, so the only way to replace it is a
-- deliberate delete. The zero-row result means "someone else won the race", and the
-- caller re-reads instead of trusting what it tried to write.
-- name: InsertPKIEntryIfAbsent :execrows
INSERT INTO pki (id, cert_pem, key_enc)
VALUES (sqlc.arg(id), sqlc.arg(cert_pem), sqlc.arg(key_enc))
ON CONFLICT (id) DO NOTHING;
