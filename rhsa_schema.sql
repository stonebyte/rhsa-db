-- ============================================================
-- RHSA Local SQLite Database Schema (v2 – CSAF 2.0 compatible)
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
-- 1. Core advisory table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS advisories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rhsa_id         TEXT    NOT NULL UNIQUE,          -- e.g. 'RHSA-2024:1234'
    title           TEXT    NOT NULL,
    severity        TEXT,                              -- Critical, Important, Moderate, Low
    type            TEXT,                              -- Security Advisory, Bug Fix, Enhancement
    description     TEXT,
    summary         TEXT,
    solution        TEXT,
    issued_date     TEXT    NOT NULL,                  -- ISO-8601 date (YYYY-MM-DD)
    updated_date    TEXT,                              -- ISO-8601 date
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
    cve_id              TEXT    NOT NULL UNIQUE,       -- e.g. 'CVE-2024-12345'
    cvss3_score         REAL,                          -- 0.0 - 10.0
    cvss3_vector        TEXT,                          -- e.g. 'CVSS:3.1/AV:N/AC:L/...'
    cvss2_score         REAL,
    cvss2_vector        TEXT,
    cwe_id              TEXT,                          -- e.g. 'CWE-79'
    impact              TEXT,                          -- Critical, Important, Moderate, Low
    description         TEXT,
    public_date         TEXT,                          -- date CVE became publicly known (from Red Hat)
    nvd_published_date  TEXT,                          -- NVD's publishedDate (from NIST NVD API)
    nvd_modified_date   TEXT,                          -- NVD's lastModifiedDate
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
-- 4. Affected / fixed packages (CSAF 2.0 compatible)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS packages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    csaf_product_id TEXT,                              -- CSAF product_id (canonical key in product_tree)
    name            TEXT    NOT NULL,                  -- source RPM or package name
    nevra           TEXT    NOT NULL,                  -- full Name-Epoch:Version-Release.Arch
    epoch           TEXT,
    version         TEXT,
    release         TEXT,
    arch            TEXT,
    product_name    TEXT,                              -- e.g. 'Red Hat Enterprise Linux 9'
    product_status  TEXT    DEFAULT 'fixed',           -- fixed, known_affected, known_not_affected, under_investigation
    purl            TEXT,                              -- Package URL (pkg:rpm/redhat/...)
    repository      TEXT,                              -- e.g. 'rhel-9-for-x86_64-baseos-rpms'
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_packages_advisory       ON packages(advisory_id);
CREATE INDEX IF NOT EXISTS idx_packages_name           ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_arch           ON packages(arch);
CREATE INDEX IF NOT EXISTS idx_packages_product        ON packages(product_name);
CREATE INDEX IF NOT EXISTS idx_packages_product_status ON packages(product_status);
CREATE INDEX IF NOT EXISTS idx_packages_purl           ON packages(purl);

-- ------------------------------------------------------------
-- 5. External references (URLs)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS references_ (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    url             TEXT    NOT NULL,
    type            TEXT,                              -- 'self', 'external', etc.
    description     TEXT
);

CREATE INDEX IF NOT EXISTS idx_references_advisory ON references_(advisory_id);

-- ------------------------------------------------------------
-- 6. Linked Bugzilla entries
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bugzillas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    bugzilla_id     TEXT    NOT NULL,                  -- e.g. '2187234'
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
    module_name     TEXT    NOT NULL,                  -- e.g. 'nodejs'
    stream          TEXT    NOT NULL,                  -- e.g. '18'
    version         TEXT,
    context         TEXT,
    arch            TEXT
);

CREATE INDEX IF NOT EXISTS idx_modules_advisory ON advisory_modules(advisory_id);

-- ------------------------------------------------------------
-- 8. Remediations (from CSAF vulnerabilities)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id     INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cve_id          TEXT,                              -- e.g. 'CVE-2024-12345'
    category        TEXT,                              -- vendor_fix, workaround, mitigation, none_available
    details         TEXT,
    url             TEXT,                              -- link to errata / fix
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_remediations_advisory ON remediations(advisory_id);
CREATE INDEX IF NOT EXISTS idx_remediations_cve      ON remediations(cve_id);
CREATE INDEX IF NOT EXISTS idx_remediations_category ON remediations(category);

-- ============================================================
-- Views (always recreated to match current table definitions)
-- ============================================================

DROP VIEW IF EXISTS v_advisory_max_cvss;
CREATE VIEW v_advisory_max_cvss AS
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

DROP VIEW IF EXISTS v_advisory_detail;
CREATE VIEW v_advisory_detail AS
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
    p.purl,
    p.product_name,
    p.product_status
FROM advisories a
LEFT JOIN advisory_cves ac ON ac.advisory_id = a.id
LEFT JOIN cves c           ON c.id = ac.cve_id
LEFT JOIN packages p       ON p.advisory_id = a.id;

DROP VIEW IF EXISTS v_remediations;
CREATE VIEW v_remediations AS
SELECT
    a.rhsa_id,
    a.severity,
    r.cve_id,
    r.category,
    r.details,
    r.url
FROM advisories a
JOIN remediations r ON r.advisory_id = a.id;