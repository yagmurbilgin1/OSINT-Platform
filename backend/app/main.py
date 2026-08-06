from flask import Flask, render_template, request
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

app = Flask(__name__)

# Veritabanını oluştur
create_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/search", methods=["POST"])
def search():

    keyword = request.form["keyword"]

    # Arama kelimesini veritabanına kaydet
    save_search(keyword)

    results = search_security(keyword)

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


if __name__ == "__main__":
    app.run(debug=True)