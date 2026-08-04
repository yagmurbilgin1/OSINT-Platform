from flask import Flask, render_template, request
from crawler import search_security

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/search", methods=["POST"])
def search():

    keyword = request.form["keyword"]

    results = search_security(keyword)

    return render_template(
        "results.html",
        results=results
    )


if __name__ == "__main__":
    app.run(debug=True)