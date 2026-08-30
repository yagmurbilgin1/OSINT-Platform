import sqlite3
from pathlib import Path


# ============================================================
# DATABASE PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DB_NAME = BASE_DIR / "osint.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    return sqlite3.connect(str(DB_NAME))


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    conn = get_connection()
    cursor = conn.cursor()

    # ========================================================
    # SEARCHES
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL,
            search_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ========================================================
    # SOURCES
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            source_type TEXT DEFAULT 'web',
            approved INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ========================================================
    # DEFAULT SOURCES
    # ========================================================

    default_sources = [

        (
            "NVD",
            "https://nvd.nist.gov/",
            "cve",
            1,
            1
        ),

        (
            "CISA Known Exploited Vulnerabilities",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "advisory",
            1,
            1
        ),

        (
            "CISA Cybersecurity Advisories",
            "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "advisory",
            1,
            1
        ),

        (
            "CERT-EU",
            "https://cert.europa.eu/",
            "advisory",
            1,
            1
        ),

        (
            "GitHub Security Advisories",
            "https://github.com/advisories",
            "advisory",
            1,
            1
        )
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO sources
        (
            name,
            url,
            source_type,
            approved,
            enabled
        )
        VALUES (?, ?, ?, ?, ?)
    """, default_sources)

    # ========================================================
    # CRAWL JOBS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crawl_jobs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            status TEXT NOT NULL
                DEFAULT 'queued',

            progress INTEGER
                DEFAULT 0,

            started_at TIMESTAMP,

            completed_at TIMESTAMP,

            pages_visited INTEGER
                DEFAULT 0,

            records_extracted INTEGER
                DEFAULT 0,

            error_count INTEGER
                DEFAULT 0,

            configuration TEXT
        )
    """)

    # ========================================================
    # ADVISORIES
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS advisories (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT,

            organization TEXT,

            publication_date TIMESTAMP,

            url TEXT,

            source_domain TEXT,

            cve TEXT,

            product TEXT,

            severity TEXT,

            summary TEXT,

            collection_date TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            crawl_job_id INTEGER
        )
    """)

    # ========================================================
    # CRAWL LOGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crawl_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            crawl_job_id INTEGER,

            timestamp TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            log_level TEXT,

            message TEXT,

            source TEXT
        )
    """)

    # ========================================================
    # SAVE
    # ========================================================

    conn.commit()
    conn.close()


# ============================================================
# SEARCH FUNCTIONS
# ============================================================

def save_search(keyword):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO searches (keyword)
        VALUES (?)
        """,
        (keyword,)
    )

    conn.commit()
    conn.close()


def get_searches():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            keyword,
            search_date
        FROM searches
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def total_searches():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM searches"
    )

    total = cursor.fetchone()[0]

    conn.close()

    return total


def most_searched():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            keyword,
            COUNT(*)
        FROM searches
        GROUP BY keyword
        ORDER BY COUNT(*) DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    conn.close()

    if result:

        return result[0]

    return "Yok"


def last_search():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT keyword
        FROM searches
        ORDER BY id DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    conn.close()

    if result:

        return result[0]

    return "Yok"


def today_searches():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM searches
        WHERE DATE(search_date) = DATE('now')
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


# ============================================================
# SOURCE FUNCTIONS
# ============================================================

def add_source(
    name,
    url,
    source_type="web",
    approved=0,
    enabled=1
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO sources
        (
            name,
            url,
            source_type,
            approved,
            enabled
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        name,
        url,
        source_type,
        approved,
        enabled
    ))

    conn.commit()
    conn.close()


def get_sources():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            url,
            source_type,
            approved,
            enabled,
            created_at
        FROM sources
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_active_sources():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            url,
            source_type
        FROM sources
        WHERE approved = 1
        AND enabled = 1
        ORDER BY id
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def update_source_status(
    source_id,
    enabled
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sources
        SET enabled = ?
        WHERE id = ?
    """, (
        enabled,
        source_id
    ))

    conn.commit()
    conn.close()


def approve_source(source_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sources
        SET approved = 1
        WHERE id = ?
    """, (source_id,))

    conn.commit()
    conn.close()


# ============================================================
# CRAWL JOB FUNCTIONS
# ============================================================

def create_crawl_job(configuration):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO crawl_jobs
        (
            status,
            progress,
            pages_visited,
            records_extracted,
            error_count,
            configuration
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        "queued",
        0,
        0,
        0,
        0,
        configuration
    ))

    job_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return job_id


def update_crawl_job(
    job_id,
    status,
    progress=0,
    pages_visited=0,
    records_extracted=0,
    error_count=0
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE crawl_jobs
        SET
            status = ?,
            progress = ?,
            pages_visited = ?,
            records_extracted = ?,
            error_count = ?
        WHERE id = ?
    """, (
        status,
        progress,
        pages_visited,
        records_extracted,
        error_count,
        job_id
    ))

    conn.commit()
    conn.close()


# ============================================================
# ADVISORY FUNCTIONS
# ============================================================

def save_advisory(
    title,
    organization,
    publication_date,
    url,
    source_domain,
    cve,
    product,
    severity,
    summary,
    crawl_job_id=None
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO advisories
        (
            title,
            organization,
            publication_date,
            url,
            source_domain,
            cve,
            product,
            severity,
            summary,
            crawl_job_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        organization,
        publication_date,
        url,
        source_domain,
        cve,
        product,
        severity,
        summary,
        crawl_job_id
    ))

    advisory_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return advisory_id


# ============================================================
# CRAWL LOG FUNCTIONS
# ============================================================

def add_crawl_log(
    job_id,
    log_level,
    message,
    source
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO crawl_logs
        (
            crawl_job_id,
            log_level,
            message,
            source
        )
        VALUES (?, ?, ?, ?)
    """, (
        job_id,
        log_level,
        message,
        source
    ))

    conn.commit()
    conn.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

if __name__ == "__main__":

    create_database()

    print("Database oluşturuldu:")
    print(DB_NAME)