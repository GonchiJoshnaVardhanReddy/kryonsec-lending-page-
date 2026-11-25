CREATE TABLE IF NOT EXISTS portal_users (
 id TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK(provider IN ('github','google')), subject TEXT NOT NULL,
 email TEXT NOT NULL, name TEXT NOT NULL, profile_url TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, updated INTEGER NOT NULL,
 UNIQUE(provider,subject)
);
CREATE TABLE IF NOT EXISTS portal_sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS portal_sessions_user ON portal_sessions(user_id);
CREATE TABLE IF NOT EXISTS portal_oauth (state_hash TEXT PRIMARY KEY,provider TEXT NOT NULL,verifier TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS portal_limits (key TEXT PRIMARY KEY,count INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS portal_applications (
 id TEXT PRIMARY KEY,user_id TEXT NOT NULL UNIQUE REFERENCES portal_users(id) ON DELETE CASCADE,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','needs_changes','revoked')),
 answers TEXT NOT NULL,policy_version TEXT NOT NULL,accepted INTEGER NOT NULL,submitted INTEGER NOT NULL,updated INTEGER NOT NULL,
 version INTEGER NOT NULL DEFAULT 1,reviewed_by TEXT,reviewed INTEGER,decision_message TEXT NOT NULL DEFAULT '',admin_note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS portal_applications_status ON portal_applications(status,submitted);
CREATE TABLE IF NOT EXISTS portal_audit (id INTEGER PRIMARY KEY AUTOINCREMENT,application_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,from_status TEXT,to_status TEXT,created INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS portal_submission_audit AFTER INSERT ON portal_applications BEGIN
 INSERT INTO portal_audit(application_id,actor,action,from_status,to_status,created) VALUES(NEW.id,NEW.user_id,'submitted',NULL,NEW.status,NEW.submitted);
END;
CREATE TRIGGER IF NOT EXISTS portal_review_audit AFTER UPDATE ON portal_applications BEGIN
 INSERT INTO portal_audit(application_id,actor,action,from_status,to_status,created) VALUES(NEW.id,CASE WHEN NEW.status='pending' THEN NEW.user_id ELSE NEW.reviewed_by END,CASE WHEN NEW.status='pending' THEN 'resubmitted' ELSE 'reviewed' END,OLD.status,NEW.status,NEW.updated);
END;
