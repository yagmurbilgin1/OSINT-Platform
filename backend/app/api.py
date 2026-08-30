from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel, Field
from pathlib import Path

import sqlite3
import json

from .crawler import search_security
from .security import is_safe_url


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DB_NAME = BASE_DIR / "osint.db"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="OSINT Platform API",
    description="OSINT Platform REST API",
    version="1.0.0"
)


# ============================================================
# TEMPLATES
# ============================================================

templates = Jinja2Templates(
    directory=str(TEMPLATES_DIR)
)


# ============================================================
# STATIC FILES
# ============================================================

if STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static"
    )


# ============================================================
# DATABASE
# ============================================================

def get_db():
    return sqlite3.connect(str(DB_NAME))


# ============================================================
# SOURCE HELPERS
# ============================================================

def get_source_name(source_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT name, source_type, url
            FROM sources
            WHERE id = ?
            """,
            (source_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        name = str(row[0] or "").upper()
        source_type = str(row[1] or "").upper()
        url = str(row[2] or "").upper()

        text = f"{name} {source_type} {url}"

        if "CISA" in text:
            return "CISA"

        if "NVD" in text:
            return "NVD"

        return row[0]

    finally:
        conn.close()


def get_selected_sources(source_ids):
    """
    source_ids boşsa NVD varsayılan olarak kullanılır.
    """

    if not source_ids:
        return ["NVD"]

    sources = []

    for source_id in source_ids:
        source = get_source_name(source_id)

        if source in ["NVD", "CISA"]:
            if source not in sources:
                sources.append(source)

    if not sources:
        return ["NVD"]

    return sources


# ============================================================
# REQUEST MODELS
# ============================================================

class CrawlRequest(BaseModel):

    source_ids: list[int] = Field(
        default_factory=list
    )

    maximum_pages: int = Field(
        default=100,
        ge=1,
        le=1000
    )

    date_from: str | None = None

    keywords: list[str] = Field(
        default_factory=list
    )

    severity: str = "ALL"


class SourceRequest(BaseModel):

    name: str

    base_url: str

    enabled: bool = True

    request_delay_seconds: float = Field(
        default=2,
        ge=0
    )


class SourceStatusRequest(BaseModel):

    enabled: bool


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request
        }
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )

        tables = cursor.fetchall()

        conn.close()

        required_tables = {
            "searches",
            "sources",
            "crawl_jobs",
            "advisories",
            "crawl_logs"
        }

        existing_tables = {
            table[0]
            for table in tables
        }

        database_ok = required_tables.issubset(
            existing_tables
        )

        return {
            "status":
                "healthy"
                if database_ok
                else "degraded",
            "database":
                "connected"
                if database_ok
                else "incomplete",
            "crawler":
                "available"
        }

    except Exception:

        return {
            "status": "unhealthy",
            "database": "disconnected",
            "crawler": "available"
        }


# ============================================================
# CVE SEARCH API
# ============================================================

@app.get("/api/cve")
def get_cve(
    keyword: str,
    severity: str = "ALL",
    source: str = "NVD"
):

    if not keyword.strip():

        raise HTTPException(
            status_code=400,
            detail="Keyword boş olamaz"
        )

    allowed_severity = [
        "ALL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    severity = severity.upper()

    if severity not in allowed_severity:

        raise HTTPException(
            status_code=400,
            detail="Geçersiz severity değeri"
        )

    source = source.upper().strip()

    if source in [
        "CISA KEV",
        "CISA KNOWN EXPLOITED VULNERABILITIES"
    ]:
        source = "CISA"

    if source not in ["NVD", "CISA"]:

        raise HTTPException(
            status_code=400,
            detail="Geçersiz kaynak"
        )

    try:

        results = search_security(
            keyword,
            severity,
            source
        )

        conn = get_db()
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

        return {
            "keyword": keyword,
            "severity": severity,
            "source": source,
            "count": len(results),
            "results": results
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"CVE verileri alınırken hata oluştu: {str(e)}"
        )


# ============================================================
# SOURCE LIST
# ============================================================

@app.get("/api/sources")
def list_sources():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
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
        """
    )

    rows = cursor.fetchall()

    conn.close()

    sources = []

    for row in rows:

        sources.append({
            "id": row[0],
            "name": row[1],
            "base_url": row[2],
            "source_type": row[3],
            "approved": bool(row[4]),
            "enabled": bool(row[5]),
            "created_at": row[6]
        })

    return {
        "count": len(sources),
        "sources": sources
    }


# ============================================================
# ADD SOURCE
# ============================================================

@app.post("/api/sources")
def add_source(
    source: SourceRequest
):

    if not is_safe_url(source.base_url):

        raise HTTPException(
            status_code=400,
            detail="Güvenli olmayan veya geçersiz kaynak URL'si"
        )

    conn = get_db()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO sources
            (
                name,
                url,
                source_type,
                approved,
                enabled
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                source.name,
                source.base_url,
                "web",
                0,
                1 if source.enabled else 0
            )
        )

        source_id = cursor.lastrowid

        conn.commit()

        return {
            "message": "Kaynak oluşturuldu",
            "source_id": source_id
        }

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=400,
            detail="Bu kaynak zaten kayıtlı"
        )

    finally:

        conn.close()


# ============================================================
# UPDATE SOURCE
# ============================================================

@app.put("/api/sources/{source_id}")
def update_source(
    source_id: int,
    source: SourceRequest
):

    if not is_safe_url(source.base_url):

        raise HTTPException(
            status_code=400,
            detail="Güvenli olmayan veya geçersiz kaynak URL'si"
        )

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM sources
        WHERE id = ?
        """,
        (source_id,)
    )

    existing = cursor.fetchone()

    if existing is None:

        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Kaynak bulunamadı"
        )

    try:

        cursor.execute(
            """
            UPDATE sources
            SET
                name = ?,
                url = ?,
                enabled = ?
            WHERE id = ?
            """,
            (
                source.name,
                source.base_url,
                1 if source.enabled else 0,
                source_id
            )
        )

        conn.commit()

        return {
            "message": "Kaynak güncellendi",
            "source_id": source_id
        }

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=400,
            detail="Bu URL başka bir kaynak tarafından kullanılıyor"
        )

    finally:

        conn.close()


# ============================================================
# ENABLE / DISABLE SOURCE
# ============================================================

@app.patch("/api/sources/{source_id}/status")
def update_source_status(
    source_id: int,
    request: SourceStatusRequest
):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM sources
        WHERE id = ?
        """,
        (source_id,)
    )

    source = cursor.fetchone()

    if source is None:

        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Kaynak bulunamadı"
        )

    cursor.execute(
        """
        UPDATE sources
        SET enabled = ?
        WHERE id = ?
        """,
        (
            1 if request.enabled else 0,
            source_id
        )
    )

    conn.commit()
    conn.close()

    return {
        "message": "Kaynak durumu güncellendi",
        "source_id": source_id,
        "enabled": request.enabled
    }


# ============================================================
# CRAWL LOG
# ============================================================

def add_crawl_log(
    job_id,
    log_level,
    message,
    source
):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO crawl_logs
        (
            crawl_job_id,
            log_level,
            message,
            source
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            job_id,
            log_level,
            message,
            source
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# BACKGROUND CRAWL
# ============================================================

def run_crawl_job(
    job_id: int,
    keyword: str,
    severity: str,
    source_ids: list[int]
):

    conn = get_db()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            UPDATE crawl_jobs
            SET
                status = ?,
                progress = ?,
                started_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                "running",
                10,
                job_id
            )
        )

        conn.commit()
        conn.close()

        selected_sources = get_selected_sources(
            source_ids
        )

        add_crawl_log(
            job_id,
            "INFO",
            f"Crawl işlemi başlatıldı. Kaynaklar: {', '.join(selected_sources)}",
            "SYSTEM"
        )

        total_inserted = 0
        total_duplicates = 0
        total_results = 0

        for source in selected_sources:

            add_crawl_log(
                job_id,
                "INFO",
                f"{source} kaynağından veri alınıyor.",
                source
            )

            results = search_security(
                keyword,
                severity,
                source
            )

            total_results += len(results)

            conn = get_db()
            cursor = conn.cursor()

            for result in results:

                cve_value = (
                    result.get("cve")
                    or result.get("id")
                    or result.get("title")
                )

                link_value = result.get("link")

                existing = None

                if cve_value:

                    cursor.execute(
                        """
                        SELECT id
                        FROM advisories
                        WHERE cve = ?
                        LIMIT 1
                        """,
                        (cve_value,)
                    )

                    existing = cursor.fetchone()

                if existing is None and link_value:

                    cursor.execute(
                        """
                        SELECT id
                        FROM advisories
                        WHERE url = ?
                        LIMIT 1
                        """,
                        (link_value,)
                    )

                    existing = cursor.fetchone()

                if existing:

                    total_duplicates += 1
                    continue

                cursor.execute(
                    """
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
                    """,
                    (
                        result.get("title"),
                        source,
                        result.get("published"),
                        link_value,
                        (
                            "nvd.nist.gov"
                            if source == "NVD"
                            else "cisa.gov"
                        ),
                        cve_value,
                        result.get("product"),
                        result.get("severity"),
                        result.get("description"),
                        job_id
                    )
                )

                total_inserted += 1

            conn.commit()
            conn.close()

            add_crawl_log(
                job_id,
                "INFO",
                (
                    f"{source} tamamlandı. "
                    f"{len(results)} sonuç bulundu."
                ),
                source
            )

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE crawl_jobs
            SET
                status = ?,
                progress = ?,
                completed_at = CURRENT_TIMESTAMP,
                pages_visited = ?,
                records_extracted = ?,
                error_count = ?
            WHERE id = ?
            """,
            (
                "completed",
                100,
                len(selected_sources),
                total_inserted,
                0,
                job_id
            )
        )

        conn.commit()
        conn.close()

        add_crawl_log(
            job_id,
            "INFO",
            (
                f"Crawl tamamlandı. "
                f"{total_inserted} yeni kayıt eklendi, "
                f"{total_duplicates} duplicate kayıt atlandı, "
                f"{total_results} toplam sonuç işlendi."
            ),
            "SYSTEM"
        )

    except Exception as e:

        try:

            conn = get_db()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE crawl_jobs
                SET
                    status = ?,
                    completed_at = CURRENT_TIMESTAMP,
                    error_count = error_count + 1
                WHERE id = ?
                """,
                (
                    "failed",
                    job_id
                )
            )

            conn.commit()
            conn.close()

        except Exception:
            pass

        try:

            add_crawl_log(
                job_id,
                "ERROR",
                f"Crawl sırasında hata oluştu: {str(e)}",
                "SYSTEM"
            )

        except Exception:
            pass


# ============================================================
# CREATE CRAWL
# ============================================================

@app.post("/api/crawls")
def create_crawl(
    request: CrawlRequest,
    background_tasks: BackgroundTasks
):

    severity = request.severity.upper()

    allowed_severity = [
        "ALL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    if severity not in allowed_severity:

        raise HTTPException(
            status_code=400,
            detail="Geçersiz severity değeri"
        )

    selected_sources = get_selected_sources(
        request.source_ids
    )

    if request.keywords:

        keyword = request.keywords[0]

    else:

        keyword = "vulnerability"

    conn = get_db()
    cursor = conn.cursor()

    configuration = json.dumps({
        "source_ids": request.source_ids,
        "sources": selected_sources,
        "maximum_pages": request.maximum_pages,
        "date_from": request.date_from,
        "keywords": request.keywords,
        "severity": severity
    })

    cursor.execute(
        """
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
        """,
        (
            "queued",
            0,
            0,
            0,
            0,
            configuration
        )
    )

    job_id = cursor.lastrowid

    conn.commit()
    conn.close()

    background_tasks.add_task(
        run_crawl_job,
        job_id,
        keyword,
        severity,
        request.source_ids
    )

    return {
        "message": "Crawl job oluşturuldu",
        "job_id": job_id,
        "status": "queued",
        "sources": selected_sources
    }


# ============================================================
# LIST CRAWLS
# ============================================================

@app.get("/api/crawls")
def list_crawls():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            status,
            progress,
            started_at,
            completed_at,
            pages_visited,
            records_extracted,
            error_count
        FROM crawl_jobs
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    jobs = []

    for row in rows:

        jobs.append({
            "id": row[0],
            "status": row[1],
            "progress": row[2],
            "started_at": row[3],
            "completed_at": row[4],
            "pages_visited": row[5],
            "records_extracted": row[6],
            "error_count": row[7]
        })

    return {
        "count": len(jobs),
        "jobs": jobs
    }


# ============================================================
# GET CRAWL STATUS
# ============================================================

@app.get("/api/crawls/{job_id}")
def get_crawl(job_id: int):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            status,
            progress,
            started_at,
            completed_at,
            pages_visited,
            records_extracted,
            error_count,
            configuration
        FROM crawl_jobs
        WHERE id = ?
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    conn.close()

    if job is None:

        raise HTTPException(
            status_code=404,
            detail="Crawl job bulunamadı"
        )

    return {
        "id": job[0],
        "status": job[1],
        "progress": job[2],
        "started_at": job[3],
        "completed_at": job[4],
        "pages_visited": job[5],
        "records_extracted": job[6],
        "error_count": job[7],
        "configuration": job[8]
    }


# ============================================================
# STOP CRAWL
# ============================================================

@app.post("/api/crawls/{job_id}/stop")
def stop_crawl(job_id: int):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT status
        FROM crawl_jobs
        WHERE id = ?
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    if job is None:

        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Crawl job bulunamadı"
        )

    if job[0] not in [
        "queued",
        "running"
    ]:

        conn.close()

        raise HTTPException(
            status_code=400,
            detail="Bu crawl job durdurulamaz"
        )

    cursor.execute(
        """
        UPDATE crawl_jobs
        SET status = ?
        WHERE id = ?
        """,
        (
            "stopping",
            job_id
        )
    )

    conn.commit()
    conn.close()

    add_crawl_log(
        job_id,
        "INFO",
        "Crawl durdurma isteği alındı",
        "SYSTEM"
    )

    return {
        "message": "Crawl job durdurma isteği gönderildi",
        "job_id": job_id,
        "status": "stopping"
    }


# ============================================================
# LIST ADVISORIES
# ============================================================

@app.get("/api/advisories")
def list_advisories(
    severity: str | None = None,
    organization: str | None = None,
    keyword: str | None = None,
    page: int = 1,
    page_size: int = 25
):

    if page < 1:
        page = 1

    if page_size < 1:
        page_size = 25

    if page_size > 100:
        page_size = 100

    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT
            id,
            title,
            organization,
            publication_date,
            url,
            source_domain,
            cve,
            product,
            severity,
            summary,
            collection_date,
            crawl_job_id
        FROM advisories
        WHERE 1 = 1
    """

    params = []

    if severity:

        query += """
            AND UPPER(severity) = ?
        """

        params.append(
            severity.upper()
        )

    if organization:

        query += """
            AND LOWER(organization) LIKE ?
        """

        params.append(
            f"%{organization.lower()}%"
        )

    if keyword:

        query += """
            AND (
                LOWER(title) LIKE ?
                OR LOWER(summary) LIKE ?
                OR LOWER(cve) LIKE ?
            )
        """

        search_value = (
            f"%{keyword.lower()}%"
        )

        params.extend([
            search_value,
            search_value,
            search_value
        ])

    query += """
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """

    offset = (
        page - 1
    ) * page_size

    params.extend([
        page_size,
        offset
    ])

    cursor.execute(
        query,
        params
    )

    rows = cursor.fetchall()

    conn.close()

    advisories = []

    for row in rows:

        advisories.append({
            "id": row[0],
            "title": row[1],
            "organization": row[2],
            "publication_date": row[3],
            "url": row[4],
            "source_domain": row[5],
            "cve": row[6],
            "product": row[7],
            "severity": row[8],
            "summary": row[9],
            "collection_date": row[10],
            "crawl_job_id": row[11]
        })

    return {
        "page": page,
        "page_size": page_size,
        "count": len(advisories),
        "advisories": advisories
    }


# ============================================================
# RECENT ADVISORIES
# ============================================================

@app.get("/api/advisories/recent")
def recent_advisories(
    limit: int = 10
):

    if limit < 1:
        limit = 10

    if limit > 50:
        limit = 50

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            title,
            organization,
            publication_date,
            url,
            severity,
            summary
        FROM advisories
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()

    advisories = []

    for row in rows:

        advisories.append({
            "id": row[0],
            "title": row[1],
            "organization": row[2],
            "publication_date": row[3],
            "url": row[4],
            "severity": row[5],
            "summary": row[6]
        })

    return {
        "count": len(advisories),
        "advisories": advisories
    }


# ============================================================
# ADVISORY DETAILS
# ============================================================

@app.get("/api/advisories/{advisory_id}")
def get_advisory(
    advisory_id: int
):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            title,
            organization,
            publication_date,
            url,
            source_domain,
            cve,
            product,
            severity,
            summary,
            collection_date,
            crawl_job_id
        FROM advisories
        WHERE id = ?
        """,
        (advisory_id,)
    )

    row = cursor.fetchone()

    conn.close()

    if row is None:

        raise HTTPException(
            status_code=404,
            detail="Advisory bulunamadı"
        )

    return {
        "id": row[0],
        "title": row[1],
        "organization": row[2],
        "publication_date": row[3],
        "url": row[4],
        "source_domain": row[5],
        "cve": row[6],
        "product": row[7],
        "severity": row[8],
        "summary": row[9],
        "collection_date": row[10],
        "crawl_job_id": row[11]
    }


# ============================================================
# DELETE ADVISORY
# ============================================================

@app.delete("/api/advisories/{advisory_id}")
def delete_advisory(
    advisory_id: int
):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM advisories
        WHERE id = ?
        """,
        (advisory_id,)
    )

    advisory = cursor.fetchone()

    if advisory is None:

        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Advisory bulunamadı"
        )

    cursor.execute(
        """
        DELETE FROM advisories
        WHERE id = ?
        """,
        (advisory_id,)
    )

    conn.commit()
    conn.close()

    return {
        "message": "Advisory silindi",
        "advisory_id": advisory_id
    }


# ============================================================
# CRAWL LOGS
# ============================================================

@app.get("/api/crawls/{job_id}/logs")
def get_crawl_logs(
    job_id: int
):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM crawl_jobs
        WHERE id = ?
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    if job is None:

        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Crawl job bulunamadı"
        )

    cursor.execute(
        """
        SELECT
            id,
            log_level,
            message,
            source,
            timestamp
        FROM crawl_logs
        WHERE crawl_job_id = ?
        ORDER BY id ASC
        """,
        (job_id,)
    )

    rows = cursor.fetchall()

    conn.close()

    logs = []

    for row in rows:

        logs.append({
            "id": row[0],
            "log_level": row[1],
            "message": row[2],
            "source": row[3],
            "created_at": row[4]
        })

    return {
        "job_id": job_id,
        "count": len(logs),
        "logs": logs
    }


# ============================================================
# DASHBOARD API SUMMARY
# ============================================================

@app.get("/api/dashboard")
def dashboard_summary():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM advisories"
    )

    total_advisories = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT
            UPPER(severity),
            COUNT(*)
        FROM advisories
        GROUP BY UPPER(severity)
        """
    )

    severity_rows = cursor.fetchall()

    severity_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for severity, count in severity_rows:

        if severity in severity_counts:
            severity_counts[severity] = count

    cursor.execute(
        "SELECT COUNT(*) FROM sources"
    )

    total_sources = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM sources
        WHERE enabled = 1
        """
    )

    active_sources = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM crawl_jobs"
    )

    total_crawls = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM crawl_jobs
        WHERE status = 'completed'
        """
    )

    completed_crawls = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM searches"
    )

    total_searches = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT
            keyword,
            COUNT(*) AS search_count
        FROM searches
        GROUP BY keyword
        ORDER BY search_count DESC
        LIMIT 1
        """
    )

    top_search_row = cursor.fetchone()

    most_searched = (
        top_search_row[0]
        if top_search_row
        else "Henüz arama yok"
    )

    cursor.execute(
        """
        SELECT keyword
        FROM searches
        ORDER BY id DESC
        LIMIT 1
        """
    )

    last_search_row = cursor.fetchone()

    last_search = (
        last_search_row[0]
        if last_search_row
        else "Henüz arama yok"
    )

    today_searches = 0

    try:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM searches
            WHERE DATE(search_date) = DATE('now')
            """
        )

        today_searches = cursor.fetchone()[0]

    except Exception:

        today_searches = 0

    conn.close()

    return {
        "total_advisories": total_advisories,
        "severity": severity_counts,
        "total_sources": total_sources,
        "active_sources": active_sources,
        "total_crawls": total_crawls,
        "completed_crawls": completed_crawls,
        "total_searches": total_searches,
        "most_searched": most_searched,
        "last_search": last_search,
        "today_searches": today_searches
    }


# ============================================================
# DASHBOARD WEB PAGE
# ============================================================

@app.get("/dashboard")
def dashboard_page(
    request: Request
):

    total = 0
    top = "Henüz arama yok"
    last = "Henüz arama yok"
    today = 0

    conn = None

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'searches'
            """
        )

        searches_exists = cursor.fetchone()

        if searches_exists:

            cursor.execute(
                "SELECT COUNT(*) FROM searches"
            )

            total = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT
                    keyword,
                    COUNT(*) AS search_count
                FROM searches
                GROUP BY keyword
                ORDER BY search_count DESC
                LIMIT 1
                """
            )

            top_row = cursor.fetchone()

            if top_row:
                top = top_row[0]

            cursor.execute(
                """
                SELECT keyword
                FROM searches
                ORDER BY rowid DESC
                LIMIT 1
                """
            )

            last_row = cursor.fetchone()

            if last_row:
                last = last_row[0]

            cursor.execute(
                "PRAGMA table_info(searches)"
            )

            search_columns = cursor.fetchall()

            column_names = {
                column[1]
                for column in search_columns
            }

            date_column = None

            possible_date_columns = [
                "timestamp",
                "created_at",
                "searched_at",
                "search_date",
                "date"
            ]

            for column in possible_date_columns:

                if column in column_names:
                    date_column = column
                    break

            if date_column:

                cursor.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM searches
                    WHERE DATE("{date_column}") = DATE('now')
                    """
                )

                today = cursor.fetchone()[0]

    except Exception:

        total = 0
        top = "Henüz arama yok"
        last = "Henüz arama yok"
        today = 0

    finally:

        if conn:
            conn.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "total": total,
            "top": top,
            "last": last,
            "today": today
        }
    )


# ============================================================
# WEB SEARCH
# ============================================================

@app.post("/search")
async def web_search(
    request: Request
):

    form = await request.form()

    keyword = str(
        form.get("keyword", "")
    ).strip()

    severity = str(
        form.get("severity", "ALL")
    ).upper()

    source = str(
        form.get("source", "NVD")
    ).upper().strip()

    if not keyword:

        raise HTTPException(
            status_code=400,
            detail="Keyword boş olamaz"
        )

    allowed_severity = [
        "ALL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    if severity not in allowed_severity:

        raise HTTPException(
            status_code=400,
            detail="Geçersiz severity değeri"
        )

    if source in [
        "CISA KEV",
        "CISA KNOWN EXPLOITED VULNERABILITIES"
    ]:
        source = "CISA"

    if source not in ["NVD", "CISA"]:

        raise HTTPException(
            status_code=400,
            detail="Geçersiz kaynak"
        )

    try:

        results = search_security(
            keyword,
            severity,
            source
        )

        conn = get_db()
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

        return templates.TemplateResponse(
            request=request,
            name="results.html",
            context={
                "request": request,
                "results": results,
                "keyword": keyword,
                "severity": severity,
                "source": source
            }
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Arama sırasında hata oluştu: {str(e)}"
        )


# ============================================================
# SEARCH HISTORY WEB PAGE
# ============================================================

@app.get("/history")
def history_page(
    request: Request
):

    conn = None

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'searches'
            """
        )

        searches_exists = cursor.fetchone()

        if not searches_exists:

            searches = []

        else:

            cursor.execute(
                "PRAGMA table_info(searches)"
            )

            columns = cursor.fetchall()

            column_names = {
                column[1]
                for column in columns
            }

            date_column = None

            possible_date_columns = [
                "timestamp",
                "created_at",
                "searched_at",
                "search_date",
                "date"
            ]

            for column in possible_date_columns:

                if column in column_names:
                    date_column = column
                    break

            if date_column:

                cursor.execute(
                    f"""
                    SELECT
                        keyword,
                        "{date_column}"
                    FROM searches
                    ORDER BY rowid DESC
                    """
                )

            else:

                cursor.execute(
                    """
                    SELECT
                        keyword,
                        'Tarih bilgisi yok'
                    FROM searches
                    ORDER BY rowid DESC
                    """
                )

            searches = cursor.fetchall()

    except Exception:

        searches = []

    finally:

        if conn:
            conn.close()

    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "request": request,
            "searches": searches
        }
    )


# ============================================================
# SOURCES WEB PAGE
# ============================================================

@app.get("/sources")
def sources_page(
    request: Request
):

    return templates.TemplateResponse(
        request=request,
        name="sources.html",
        context={
            "request": request
        }
    )


# ============================================================
# CRAWLS WEB PAGE
# ============================================================

@app.get("/crawls")
def crawls_page(
    request: Request
):

    return templates.TemplateResponse(
        request=request,
        name="crawls.html",
        context={
            "request": request
        }
    )