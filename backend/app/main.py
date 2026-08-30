from flask import Flask, render_template, request, Response, make_response
from database import (
    create_database,
    save_search,
    get_searches,
    total_searches,
    most_searched,
    last_search,
    today_searches,
    get_sources,
    update_source_status,
    approve_source
)

from reportlab.pdfgen import canvas
from io import BytesIO
import requests


# ============================================================
# APP
# ============================================================

app = Flask(__name__)

create_database()

FASTAPI_URL = "http://127.0.0.1:8000"


# ============================================================
# ANA SAYFA
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# WEB SEARCH
# ============================================================

@app.route("/search", methods=["POST"])
def search():

    keyword = request.form.get(
        "keyword",
        ""
    ).strip()

    severity = request.form.get(
        "severity",
        "ALL"
    ).upper()

    if not keyword:

        return render_template(
            "results.html",
            results=[],
            keyword=keyword,
            severity=severity
        )

    save_search(keyword)

    response = requests.get(
        f"{FASTAPI_URL}/api/cve",
        params={
            "keyword": keyword,
            "severity": severity
        },
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    results = data.get(
        "results",
        []
    )

    return render_template(
        "results.html",
        results=results,
        keyword=keyword,
        severity=severity
    )


# ============================================================
# SEARCH HISTORY
# ============================================================

@app.route("/history")
def history():

    searches = get_searches()

    return render_template(
        "history.html",
        searches=searches
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    total = total_searches()
    top = most_searched()
    last = last_search()
    today = today_searches()

    return render_template(
        "dashboard.html",
        total=total,
        top=top,
        last=last,
        today=today
    )


# ============================================================
# DASHBOARD API
# ============================================================

@app.route("/api/dashboard")
def api_dashboard():

    response = requests.get(
        f"{FASTAPI_URL}/api/dashboard",
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# CSV DOWNLOAD
# ============================================================

@app.route("/download-csv")
def download_csv():

    searches = get_searches()

    csv_data = "Kelime,Tarih\n"

    for item in searches:

        csv_data += (
            f"{item[0]},{item[1]}\n"
        )

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=arama_gecmisi.csv"
        }
    )


# ============================================================
# PDF DOWNLOAD
# ============================================================

@app.route("/download-pdf")
def download_pdf():

    searches = get_searches()

    buffer = BytesIO()

    pdf = canvas.Canvas(
        buffer
    )

    pdf.setFont(
        "Helvetica-Bold",
        16
    )

    pdf.drawString(
        50,
        800,
        "OSINT Arama Gecmisi"
    )

    pdf.setFont(
        "Helvetica",
        11
    )

    y = 770

    for item in searches:

        pdf.drawString(
            50,
            y,
            f"{item[0]} - {item[1]}"
        )

        y -= 20

        if y < 50:

            pdf.showPage()

            pdf.setFont(
                "Helvetica",
                11
            )

            y = 800

    pdf.save()

    buffer.seek(0)

    response = make_response(
        buffer.getvalue()
    )

    response.headers[
        "Content-Type"
    ] = "application/pdf"

    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=arama_gecmisi.pdf"
    )

    return response


# ============================================================
# CVE API
# ============================================================

@app.route("/api/cve")
def api_cve():

    keyword = request.args.get(
        "keyword",
        ""
    )

    severity = request.args.get(
        "severity",
        "ALL"
    )

    response = requests.get(
        f"{FASTAPI_URL}/api/cve",
        params={
            "keyword": keyword,
            "severity": severity
        },
        timeout=30
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# SOURCES WEB PAGE
# ============================================================

@app.route("/sources")
def sources_page():

    return render_template(
        "sources.html"
    )


# ============================================================
# SOURCES API
# ============================================================

@app.route("/api/sources")
def api_sources():

    sources = get_sources()

    results = []

    for source in sources:

        results.append({
            "id": source[0],
            "name": source[1],
            "url": source[2],
            "source_type": source[3],
            "approved": source[4],
            "enabled": source[5],
            "created_at": source[6]
        })

    return {
        "count": len(results),
        "sources": results
    }


# ============================================================
# SOURCE STATUS
# ============================================================

@app.route(
    "/api/sources/<int:source_id>/status",
    methods=["POST"]
)
def update_source(source_id):

    data = request.get_json(
        silent=True
    ) or {}

    enabled = data.get(
        "enabled",
        1
    )

    update_source_status(
        source_id,
        enabled
    )

    return {
        "message":
            "Kaynak durumu güncellendi",

        "source_id":
            source_id,

        "enabled":
            enabled
    }


# ============================================================
# SOURCE APPROVAL
# ============================================================

@app.route(
    "/api/sources/<int:source_id>/approve",
    methods=["POST"]
)
def approve_source_api(source_id):

    approve_source(
        source_id
    )

    return {
        "message":
            "Kaynak onaylandı",

        "source_id":
            source_id
    }


# ============================================================
# CRAWLS WEB PAGE
# ============================================================

@app.route("/crawls")
def crawls_page():

    return render_template(
        "crawls.html"
    )


# ============================================================
# CRAWLS API
# ============================================================

@app.route("/api/crawls")
def api_crawls():

    response = requests.get(
        f"{FASTAPI_URL}/api/crawls",
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# CRAWL DETAIL API
# ============================================================

@app.route("/api/crawls/<int:job_id>")
def api_crawl_detail(job_id):

    response = requests.get(
        f"{FASTAPI_URL}/api/crawls/{job_id}",
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# CRAWL LOGS API
# ============================================================

@app.route("/api/crawls/<int:job_id>/logs")
def api_crawl_logs(job_id):

    response = requests.get(
        f"{FASTAPI_URL}/api/crawls/{job_id}/logs",
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# STOP CRAWL API
# ============================================================

@app.route(
    "/api/crawls/<int:job_id>/stop",
    methods=["POST"]
)
def api_stop_crawl(job_id):

    response = requests.post(
        f"{FASTAPI_URL}/api/crawls/{job_id}/stop",
        timeout=15
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# HEALTH
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return {
        "status": "ok"
    }, 200


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )