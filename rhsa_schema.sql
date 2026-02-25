-- ============================================================
-- RHSA Local SQLite Database Schema
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
-- 1. Core advisory table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS advisories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rhsa_id         TEXT    NOT NULL UNIQUE,
    title           TEXT    NOT NULL,
    severity        TEXT,
    type            TEXT,
    description     TEXT,
    summary         TEXT,
    solution        TEXT,
    issued_date     TEXT    NOT NULL,
    updated_date    TEXT,
    release_date    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_advisories_rhsa_id   ON advisories(rhsa_id);
CREATE INDEX IF NOT EXISTS idx_advisories_severity  ON advisories(severity);
CREATE INDEX IF NOT EXISTS idx_advisories_issued    ON advisories(issued_date);

-- ------------------------------------------------------------
-- 2. CVE details
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cves (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id              TEXT    NOT NULL UNIQUE,
    cvss3_score         REAL,
    cvss3_vector        TEXT,
    cvss2_score         REAL,
    cvss2_vector        TEXT,
    cwe_id              TEXT,
    impact              TEXT,
    description         TEXT,
    public_date         TEXT,
    nvd_published_date  TEXT,
    nvd_modified_date   TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id            ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_cvss3_score       ON cves(cvss3_score);
CREATE INDEX IF NOT EXISTS idx_cves_impact            ON cves(impact);
CREATE INDEX IF NOT EXISTS idx_cves_nvd_published     ON cves(nvd_published_date);

-- ------------------------------------------------------------
-- 3. Many-to-many: advisory <-> CVE
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS advisory_cves (
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cve_id          INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    PRIMARY KEY (advisory_id, cve_id)
);

-- ------------------------------------------------------------
-- 4. Affected / fixed packages
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS packages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    nevra           TEXT    NOT NULL,
    epoch           TEXT,
    version         TEXT,
    release         TEXT,
    arch            TEXT,
    product_name    TEXT,
    repository      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_packages_advisory ON packages(advisory_id);
CREATE INDEX IF NOT EXISTS idx_packages_name     ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_arch     ON packages(arch);
CREATE INDEX IF NOT EXISTS idx_packages_product  ON packages(product_name);

-- ------------------------------------------------------------
-- 5. External references (URLs)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS references_ (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    url             TEXT    NOT NULL,
    type            TEXT,
    description     TEXT
);
CREATE INDEX IF NOT EXISTS idx_references_advisory ON references_(advisory_id);

-- ------------------------------------------------------------
-- 6. Linked Bugzilla entries
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bugzillas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    bugzilla_id     TEXT    NOT NULL,
    url             TEXT,
    description     TEXT,
    UNIQUE(advisory_id, bugzilla_id)
);
CREATE INDEX IF NOT EXISTS idx_bugzillas_advisory ON bugzillas(advisory_id);

-- ------------------------------------------------------------
-- 7. Affected modules (for modular content)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS advisory_modules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    module_name     TEXT    NOT NULL,
    stream          TEXT    NOT NULL,
    version         TEXT,
    context         TEXT,
    arch            TEXT
);
CREATE INDEX IF NOT EXISTS idx_modules_advisory ON advisory_modules(advisory_id);

-- ============================================================
-- Useful views
-- ============================================================

CREATE VIEW IF NOT EXISTS v_advisory_max_cvss AS
SELECT
    a.rhsa_id,
    a.title,
    a.severity,
    a.issued_date,
    MAX(c.cvss3_score) AS max_cvss3_score
FROM advisories a
JOIN advisory_cves ac ON ac.advisory_id = a.id
JOIN cves c           ON c.id = ac.cve_id
GROUP BY a.id;

CREATE VIEW IF NOT EXISTS v_advisory_detail AS
SELECT
    a.rhsa_id,
    a.severity,
    a.issued_date,
    c.cve_id,
    c.cvss3_score,
    c.cwe_id,
    c.public_date,
    c.nvd_published_date,
    c.nvd_modified_date,
    p.nevra,
    p.product_name
FROM advisories a
LEFT JOIN advisory_cves ac ON ac.advisory_id = a.id
LEFT JOIN cves c           ON c.id = ac.cve_id
LEFT JOIN packages p       ON p.advisory_id = a.id;