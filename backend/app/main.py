from flask import Flask, render_template, request, Response, make_response
from crawler import search_security
from database import (
    create_database,
    save_search,
    get_searches,
    total_searches,
    most_searched,
    last_search,
    today_searches
)

from reportlab.pdfgen import canvas
from io import BytesIO

app = Flask(__name__)

# Veritabanını oluştur
create_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/search", methods=["POST"])
def search():

    keyword = request.form["keyword"]
    severity = request.form["severity"]

    # Arama kelimesini veritabanına kaydet
    save_search(keyword)

    results = search_security(keyword, severity)

    return render_template(
        "results.html",
        results=results
    )


@app.route("/history")
def history():

    searches = get_searches()

    return render_template(
        "history.html",
        searches=searches
    )

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


@app.route("/download-csv")
def download_csv():

    searches = get_searches()

    csv_data = "Kelime,Tarih\n"

    for item in searches:
        csv_data += f"{item[0]},{item[1]}\n"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=arama_gecmisi.csv"
        }
    )

@app.route("/download-pdf")
def download_pdf():

    searches = get_searches()

    buffer = BytesIO()

    pdf = canvas.Canvas(buffer)

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 800, "OSINT Arama Gecmisi")

    pdf.setFont("Helvetica", 11)

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
            pdf.setFont("Helvetica", 11)
            y = 800

    pdf.save()

    buffer.seek(0)

    response = make_response(buffer.getvalue())

    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=arama_gecmisi.pdf"

    return response

if __name__ == "__main__":
    app.run(debug=True)
