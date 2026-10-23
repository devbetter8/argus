-- Score de priorité sur 100, calculé à chaque synchronisation.
-- Les lignes existantes valent 0 jusqu'à la prochaine synchronisation.
ALTER TABLE vulnerability
    ADD COLUMN priority_score INT NOT NULL DEFAULT 0;

-- Accélère le tri par priorité, utilisé par défaut dans l'API.
CREATE INDEX idx_vulnerability_priority_score ON vulnerability (priority_score);
