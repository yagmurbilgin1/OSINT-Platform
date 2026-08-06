import sqlite3

DB_NAME = "osint.db"


def create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL,
            search_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_search(keyword):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO searches (keyword) VALUES (?)",
        (keyword,)
    )

    conn.commit()
    conn.close()
    
def get_searches():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT keyword, search_date
        FROM searches
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
def total_searches():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM searches")

    total = cursor.fetchone()[0]

    conn.close()

    return total


def most_searched():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT keyword, COUNT(*)
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
    conn = sqlite3.connect(DB_NAME)
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
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM searches
        WHERE DATE(search_date)=DATE('now')
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total