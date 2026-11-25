CREATE TABLE IF NOT EXISTS portal_feedback (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
 category TEXT NOT NULL CHECK(category IN ('bug','idea','experience')),
 message TEXT NOT NULL CHECK(length(message) BETWEEN 20 AND 4000),
 rating INTEGER CHECK(rating BETWEEN 1 AND 5), created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_feedback_created ON portal_feedback(created);
CREATE TABLE IF NOT EXISTS portal_beta_cards (
 number INTEGER PRIMARY KEY CHECK(number BETWEEN 1 AND 50),
 user_id TEXT UNIQUE REFERENCES portal_users(id) ON DELETE SET NULL,
 public_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '',
 published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1)), created INTEGER NOT NULL
);
-- Preserve numbers permanently, including when an account is deleted or revoked.
-- Existing approvals are allocated by first approval time, then application ID.
INSERT INTO portal_beta_cards(number,user_id,public_id,created)
SELECT row_number() OVER (ORDER BY first_approval,id),user_id,lower(hex(randomblob(32))),first_approval
FROM (SELECT a.id,a.user_id,COALESCE((SELECT min(created) FROM portal_audit WHERE application_id=a.id AND to_status='approved'),a.reviewed,a.updated) AS first_approval
 FROM portal_applications a WHERE a.status='approved')
WHERE NOT EXISTS(SELECT 1 FROM portal_beta_cards) LIMIT 50;
CREATE TRIGGER IF NOT EXISTS portal_card_on_approval AFTER UPDATE OF status ON portal_applications
WHEN NEW.status='approved' AND NOT EXISTS(SELECT 1 FROM portal_beta_cards WHERE user_id=NEW.user_id)
BEGIN
 INSERT INTO portal_beta_cards(number,user_id,public_id,created)
 SELECT COALESCE(max(number),0)+1,NEW.user_id,lower(hex(randomblob(32))),NEW.updated
 FROM portal_beta_cards HAVING COALESCE(max(number),0)<50;
END;
