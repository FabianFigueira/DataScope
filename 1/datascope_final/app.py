# 2. PYTHON AND FLASK

import os
import re
import sqlite3
from functools import wraps

# 5. PANDAS AND NUMPY
import pandas as pd
import numpy as np

from flask import Flask, render_template, request, redirect, session, flash, g
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "instance", "datascope.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "data")

os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "datascope-development-key")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

Session(app)


# 3. SQLITE - DATABASE

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_database():
    db = sqlite3.connect(DATABASE)

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            rows INTEGER NOT NULL,
            columns_count INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    db.commit()
    db.close()


initialize_database()


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return function(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return render_template("index.html")


# 4. SECURITY AND PASSWORDS

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")

        if not username or not password:
            flash("All fields are required.", "error")
            return redirect("/register")

        if len(username) > 30:
            flash("Username must contain 30 characters or fewer.", "error")
            return redirect("/register")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect("/register")

        if password != confirmation:
            flash("Passwords do not match.", "error")
            return redirect("/register")

        db = get_db()

        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect("/register")

        flash("Account created successfully. Please log in.", "success")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return redirect("/login")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect("/dashboard")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    datasets = db.execute(
        """
        SELECT * FROM datasets
        WHERE user_id = ?
        ORDER BY uploaded_at DESC
        """,
        (session["user_id"],)
    ).fetchall()

    total_rows = sum(dataset["rows"] for dataset in datasets)

    return render_template(
        "dashboard.html",
        datasets=datasets,
        total_datasets=len(datasets),
        total_rows=total_rows
    )


# 6. CSV FILE UPLOAD

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")

    if file is None or not file.filename:
        flash("Please select a CSV file.", "error")
        return redirect("/dashboard")

    if not file.filename.lower().endswith(".csv"):
        flash("Only CSV files are supported.", "error")
        return redirect("/dashboard")

    original_name = secure_filename(file.filename)

    if not original_name:
        flash("Invalid filename.", "error")
        return redirect("/dashboard")

    stored_name = f"{session['user_id']}_{os.urandom(8).hex()}.csv"
    filepath = os.path.join(UPLOAD_FOLDER, stored_name)

    try:
        file.save(filepath)
        df = pd.read_csv(filepath, nrows=100001)

        if df.empty:
            raise ValueError("The CSV file is empty.")

        if len(df) > 100000:
            raise ValueError("Maximum of 100,000 rows allowed.")

        if len(df.columns) > 100:
            raise ValueError("Maximum of 100 columns allowed.")

        db = get_db()
        db.execute(
            """
            INSERT INTO datasets
            (user_id, filename, original_name, rows, columns_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session["user_id"], stored_name, original_name, len(df), len(df.columns))
        )
        db.commit()

        flash("Dataset uploaded successfully.", "success")

    except Exception as error:
        if os.path.exists(filepath):
            os.remove(filepath)
        flash(f"Could not process CSV: {error}", "error")

    return redirect("/dashboard")


@app.route("/dataset/<int:dataset_id>")
@login_required
def dataset(dataset_id):
    db = get_db()

    dataset = db.execute(
        """
        SELECT * FROM datasets
        WHERE id = ? AND user_id = ?
        """,
        (dataset_id, session["user_id"])
    ).fetchone()

    if dataset is None:
        return redirect("/dashboard")

    filepath = os.path.join(UPLOAD_FOLDER, dataset["filename"])

    try:
        df = pd.read_csv(filepath)
    except Exception:
        flash("Could not read this dataset.", "error")
        return redirect("/dashboard")

    preview = df.head(100).replace({np.nan: None}).to_dict(orient="records")

    # 11. DATA QUALITY

    columns = [
        {
            "name": str(column),
            "dtype": str(df[column].dtype),
            "missing": int(df[column].isna().sum()),
            "unique": int(df[column].nunique())
        }
        for column in df.columns
    ]

    numeric = df.select_dtypes(include=np.number)

    # 7. DESCRIPTIVE STATISTICS

    statistics = []

    for column in numeric.columns:
        values = numeric[column].dropna()

        statistics.append({
            "name": str(column),
            "mean": float(values.mean()) if not values.empty else None,
            "median": float(values.median()) if not values.empty else None,
            "min": float(values.min()) if not values.empty else None,
            "max": float(values.max()) if not values.empty else None
        })

    # 8. CORRELATION MATRIX

    correlation_columns = [str(column) for column in numeric.columns]
    correlation_values = numeric.corr()

    correlation_matrix = []

    for column in numeric.columns:
        values = []

        for other_column in numeric.columns:
            value = correlation_values.loc[column, other_column]

            values.append(
                float(value) if pd.notna(value) else None
            )

        correlation_matrix.append({
            "name": str(column),
            "values": values
        })

    # 9. OUTLIER DETECTION

    outliers = []

    for column in numeric.columns:
        values = numeric[column].dropna()

        if values.empty:
            q1 = None
            q3 = None
            lower_bound = None
            upper_bound = None
            outlier_count = 0
        else:
            q1 = float(values.quantile(0.25))
            q3 = float(values.quantile(0.75))
            iqr = q3 - q1

            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            outlier_count = int(
                ((values < lower_bound) | (values > upper_bound)).sum()
            )

        percentage = (
            round(outlier_count / len(values) * 100, 2)
            if len(values) > 0 else 0
        )

        outliers.append({
            "name": str(column),
            "q1": q1,
            "q3": q3,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "count": outlier_count,
            "percentage": percentage
        })

    # 10. DUPLICATE RECORDS

    duplicate_count = int(df.duplicated().sum())
    duplicate_percentage = (
        round(duplicate_count / len(df) * 100, 2)
        if len(df) > 0 else 0
    )

    # 12. PRODUCT INSIGHTS

    def normalize_column(column):
        return re.sub(r"[^a-z0-9]", "", str(column).lower())

    normalized_columns = {
        normalize_column(column): column
        for column in df.columns
    }

    def find_column(aliases):
        for alias in aliases:
            normalized_alias = normalize_column(alias)

            if normalized_alias in normalized_columns:
                return normalized_columns[normalized_alias]

        return None

    product_column = find_column([
        "Product", "Product Name", "Item", "Item Name",
        "Producto", "Nombre Producto", "Articulo", "Artículo"
    ])

    quantity_column = find_column([
        "Quantity", "Units Sold", "Units", "Qty",
        "Sold", "Cantidad", "Unidades Vendidas",
        "Ventas", "Unidades", "Cantidad Vendida"
    ])

    price_column = find_column([
        "Price", "Unit Price", "Selling Price",
        "Precio", "Precio Unitario"
    ])

    revenue_column = find_column([
        "Revenue", "Total Revenue", "Total Sales",
        "Sales Revenue", "Ingresos", "Recaudacion",
        "Recaudación", "Ventas Totales"
    ])

    product_insights = {
        "available": False,
        "best_selling": None,
        "most_expensive": None,
        "highest_revenue": None,
        "missing": []
    }

    if product_column is not None:
        products = df.dropna(subset=[product_column]).copy()

        if quantity_column is not None:
            products["_quantity"] = pd.to_numeric(
                products[quantity_column], errors="coerce"
            )

            quantity_totals = products.groupby(product_column)["_quantity"].sum()
            quantity_totals = quantity_totals.dropna()

            if not quantity_totals.empty:
                best_product = quantity_totals.idxmax()

                product_insights["best_selling"] = {
                    "name": str(best_product),
                    "value": float(quantity_totals.loc[best_product])
                }
        else:
            product_insights["missing"].append("Quantity")

        if price_column is not None:
            products["_price"] = pd.to_numeric(
                products[price_column], errors="coerce"
            )

            price_totals = products.groupby(product_column)["_price"].max()
            price_totals = price_totals.dropna()

            if not price_totals.empty:
                expensive_product = price_totals.idxmax()

                product_insights["most_expensive"] = {
                    "name": str(expensive_product),
                    "value": float(price_totals.loc[expensive_product])
                }
        else:
            product_insights["missing"].append("Price")

        if revenue_column is not None:
            products["_revenue"] = pd.to_numeric(
                products[revenue_column], errors="coerce"
            )

        elif quantity_column is not None and price_column is not None:
            products["_revenue"] = (
                products["_quantity"] * products["_price"]
            )

        else:
            products["_revenue"] = np.nan
            product_insights["missing"].append("Revenue or Quantity + Price")

        revenue_totals = products.groupby(product_column)["_revenue"].sum()
        revenue_totals = revenue_totals.dropna()

        if not revenue_totals.empty:
            revenue_product = revenue_totals.idxmax()

            product_insights["highest_revenue"] = {
                "name": str(revenue_product),
                "value": float(revenue_totals.loc[revenue_product])
            }

        product_insights["available"] = any([
            product_insights["best_selling"],
            product_insights["most_expensive"],
            product_insights["highest_revenue"]
        ])

    else:
        product_insights["missing"].append("Product")

    return render_template(
        "dataset.html",
        dataset=dataset,
        preview=preview,
        columns=columns,
        statistics=statistics,
        correlation_columns=correlation_columns,
        correlation_matrix=correlation_matrix,
        outliers=outliers,
        duplicate_count=duplicate_count,
        duplicate_percentage=duplicate_percentage,
        product_insights=product_insights
    )


@app.route("/dataset/<int:dataset_id>/delete", methods=["POST"])
@login_required
def delete_dataset(dataset_id):
    db = get_db()

    dataset = db.execute(
        """
        SELECT * FROM datasets
        WHERE id = ? AND user_id = ?
        """,
        (dataset_id, session["user_id"])
    ).fetchone()

    if dataset is not None:
        filepath = os.path.join(UPLOAD_FOLDER, dataset["filename"])

        if os.path.exists(filepath):
            os.remove(filepath)

        db.execute(
            "DELETE FROM datasets WHERE id = ? AND user_id = ?",
            (dataset_id, session["user_id"])
        )
        db.commit()

        flash("Dataset deleted successfully.", "success")

    return redirect("/dashboard")


@app.errorhandler(413)
def file_too_large(error):
    flash("File exceeds the 10 MB limit.", "error")
    return redirect("/dashboard")


@app.errorhandler(404)
def not_found(error):
    return render_template("index.html"), 404


if __name__ == "__main__":
    app.run(debug=True, port=6002)
