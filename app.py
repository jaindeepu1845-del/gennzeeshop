import os
import sqlite3
import secrets
import hmac
import hashlib
import libsql

from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "shop.db"))

TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")


app = Flask(__name__)
app.secret_key = SECRET_KEY


# Products containing these names are not displayed on the website.
BLOCKED_NAME_PARTS = ("cracked",)


class CompatRow:
    """Small sqlite3.Row-compatible wrapper for remote libsql rows."""

    def __init__(self, values, description):
        self._values = tuple(values)
        self._names = [d[0] for d in (description or [])]
        self._index = {name: i for i, name in enumerate(self._names)}

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._index[key]]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


class CompatCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def description(self):
        return self._cursor.description

    def fetchone(self):
        row = self._cursor.fetchone()

        if row is None:
            return None

        return CompatRow(row, self._cursor.description)

    def fetchall(self):
        return [
            CompatRow(row, self._cursor.description)
            for row in self._cursor.fetchall()
        ]


class CompatConnection:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, *args, **kwargs):
        return CompatCursor(self._conn.execute(*args, **kwargs))

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            try:
                self.rollback()
            except Exception:
                pass

        self.close()


def db():
    # Production / Render:
    # connect directly to Turso over HTTPS.
    if TURSO_DATABASE_URL and TURSO_AUTH_TOKEN:
        conn = libsql.connect(
            database=TURSO_DATABASE_URL,
            auth_token=TURSO_AUTH_TOKEN
        )

        try:
            conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            pass

        return CompatConnection(conn)

    # Local development fallback.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass

    return conn


def allowed_product(row):
    name = (row["name"] or "").lower()
    return not any(x in name for x in BLOCKED_NAME_PARTS)


def current_user():
    uid = session.get("user_id")

    if not uid:
        return None

    with db() as c:
        return c.execute(
            "SELECT * FROM web_users WHERE id=?",
            (uid,)
        ).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user():
            return redirect(
                url_for("login", next=request.path)
            )

        return fn(*a, **kw)

    return wrapped


def init_web_tables():
    with db() as c:

        c.execute("""
            CREATE TABLE IF NOT EXISTS web_users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                wallet_balance REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS web_orders(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                total_amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                razorpay_order_id TEXT,
                razorpay_payment_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES web_users(id)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS web_order_items(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                web_order_id INTEGER NOT NULL,
                stock_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                FOREIGN KEY(web_order_id) REFERENCES web_orders(id)
            )
        """)

        c.commit()


def products():
    with db() as c:
        rows = c.execute("""
            SELECT
                p.id,
                p.name,
                p.price,
                p.description,
                p.active,
                COALESCE(
                    SUM(
                        CASE
                            WHEN s.sold=0 THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) stock
            FROM products p
            LEFT JOIN stock s
                ON s.product_id=p.id
            WHERE p.active=1
            GROUP BY p.id
            ORDER BY p.id
        """).fetchall()

    return [r for r in rows if allowed_product(r)]


@app.before_request
def bootstrap():
    init_web_tables()


@app.route("/")
def home():
    return render_template(
        "home.html",
        products=products(),
        user=current_user()
    )


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash(
                "Enter a name, valid email, and password of at least 8 characters."
            )
            return redirect(url_for("register"))

        try:
            with db() as c:

                # Check first so duplicate emails don't produce
                # a Turso UNIQUE constraint error.
                existing = c.execute(
                    "SELECT id FROM web_users WHERE email=?",
                    (email,)
                ).fetchone()

                if existing:
                    flash(
                        "That email is already registered. "
                        "Please use another email or log in."
                    )
                    return redirect(url_for("register"))

                password_hash = generate_password_hash(password)

                c.execute(
                    """
                    INSERT INTO web_users(
                        name,
                        email,
                        password_hash
                    )
                    VALUES(?,?,?)
                    """,
                    (
                        name,
                        email,
                        password_hash
                    )
                )

                c.commit()

                # Don't use cursor.lastrowid with remote libsql.
                # Find the newly created user by email instead.
                user_row = c.execute(
                    "SELECT id FROM web_users WHERE email=?",
                    (email,)
                ).fetchone()

                if not user_row:
                    flash(
                        "Account could not be created. Please try again."
                    )
                    return redirect(url_for("register"))

                session["user_id"] = user_row["id"]

            return redirect(url_for("home"))

        except Exception:
            app.logger.exception("Registration error")

            flash(
                "Unable to create the account right now. "
                "Please try again."
            )

            return redirect(url_for("register"))

    return render_template(
        "auth.html",
        mode="register",
        user=current_user()
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with db() as c:
            u = c.execute(
                "SELECT * FROM web_users WHERE email=?",
                (email,)
            ).fetchone()

        if u and check_password_hash(
            u["password_hash"],
            password
        ):
            session["user_id"] = u["id"]

            return redirect(
                request.args.get("next")
                or url_for("home")
            )

        flash("Invalid email or password.")

    return render_template(
        "auth.html",
        mode="login",
        user=current_user()
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/account")
@login_required
def account():

    u = current_user()

    with db() as c:
        orders = c.execute("""
            SELECT
                o.*,
                p.name
            FROM web_orders o
            JOIN products p
                ON p.id=o.product_id
            WHERE o.user_id=?
            ORDER BY o.id DESC
        """, (u["id"],)).fetchall()

    return render_template(
        "account.html",
        user=u,
        orders=orders
    )


@app.route("/buy/<int:product_id>", methods=["POST"])
@login_required
def buy(product_id):

    try:
        qty = int(request.form.get("quantity", 1))
    except (TypeError, ValueError):
        qty = 1

    qty = max(1, min(qty, 5))

    with db() as c:

        p = c.execute(
            """
            SELECT *
            FROM products
            WHERE id=? AND active=1
            """,
            (product_id,)
        ).fetchone()

        if not p or not allowed_product(p):
            flash("This product is unavailable.")
            return redirect(url_for("home"))

        available = c.execute(
            """
            SELECT COUNT(*)
            FROM stock
            WHERE product_id=? AND sold=0
            """,
            (product_id,)
        ).fetchone()[0]

        if available < qty:
            flash(f"Only {available} in stock.")
            return redirect(url_for("home"))

        total = float(p["price"]) * qty

        u = c.execute(
            """
            SELECT *
            FROM web_users
            WHERE id=?
            """,
            (session["user_id"],)
        ).fetchone()

        wallet_use = min(
            float(u["wallet_balance"]),
            total
        )

        remaining = round(
            total - wallet_use,
            2
        )

        c.execute(
            """
            INSERT INTO web_orders(
                user_id,
                product_id,
                quantity,
                total_amount,
                status
            )
            VALUES(?,?,?,?,?)
            """,
            (
                u["id"],
                product_id,
                qty,
                total,
                "awaiting_payment" if remaining else "paid"
            )
        )

        # Don't use lastrowid with remote libsql.
        order_row = c.execute(
            """
            SELECT id
            FROM web_orders
            WHERE user_id=?
              AND product_id=?
              AND quantity=?
              AND total_amount=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                u["id"],
                product_id,
                qty,
                total
            )
        ).fetchone()

        if not order_row:
            raise RuntimeError(
                "Could not find newly created web order."
            )

        order_id = order_row["id"]

        if wallet_use:
            c.execute(
                """
                UPDATE web_users
                SET wallet_balance=wallet_balance-?
                WHERE id=?
                """,
                (
                    wallet_use,
                    u["id"]
                )
            )

        if remaining == 0:

            rows = c.execute(
                """
                SELECT id, code
                FROM stock
                WHERE product_id=?
                  AND sold=0
                ORDER BY id
                LIMIT ?
                """,
                (
                    product_id,
                    qty
                )
            ).fetchall()

            for s in rows:

                c.execute(
                    """
                    UPDATE stock
                    SET sold=1
                    WHERE id=? AND sold=0
                    """,
                    (s["id"],)
                )

                c.execute(
                    """
                    INSERT INTO web_order_items(
                        web_order_id,
                        stock_id,
                        code
                    )
                    VALUES(?,?,?)
                    """,
                    (
                        order_id,
                        s["id"],
                        s["code"]
                    )
                )

            c.execute(
                """
                UPDATE web_orders
                SET status='delivered'
                WHERE id=?
                """,
                (order_id,)
            )

        c.commit()

    if remaining == 0:
        return redirect(
            url_for("order", order_id=order_id)
        )

    return render_template(
        "payment.html",
        order_id=order_id,
        amount=remaining,
        key_id=RAZORPAY_KEY_ID,
        razorpay_ready=bool(
            RAZORPAY_KEY_ID
            and RAZORPAY_KEY_SECRET
        )
    )


@app.route("/order/<int:order_id>")
@login_required
def order(order_id):

    with db() as c:

        o = c.execute(
            """
            SELECT
                o.*,
                p.name,
                p.price
            FROM web_orders o
            JOIN products p
                ON p.id=o.product_id
            WHERE o.id=?
              AND o.user_id=?
            """,
            (
                order_id,
                session["user_id"]
            )
        ).fetchone()

        if not o:
            return "Not found", 404

        items = c.execute(
            """
            SELECT code
            FROM web_order_items
            WHERE web_order_id=?
            """,
            (order_id,)
        ).fetchall()

    return render_template(
        "order.html",
        order=o,
        items=items,
        user=current_user()
    )


@app.post("/api/razorpay/order")
@login_required
def razorpay_order():

    if not (
        RAZORPAY_KEY_ID
        and RAZORPAY_KEY_SECRET
    ):
        return jsonify(
            error="Razorpay is not configured yet."
        ), 400

    try:

        import razorpay

        order_id = int(
            request.json["order_id"]
        )

        with db() as c:
            o = c.execute(
                """
                SELECT *
                FROM web_orders
                WHERE id=?
                  AND user_id=?
                """,
                (
                    order_id,
                    session["user_id"]
                )
            ).fetchone()

        if not o or o["status"] != "awaiting_payment":
            return jsonify(
                error="Invalid order."
            ), 400

        client = razorpay.Client(
            auth=(
                RAZORPAY_KEY_ID,
                RAZORPAY_KEY_SECRET
            )
        )

        rp = client.order.create(
            {
                "amount": int(
                    round(
                        o["total_amount"] * 100
                    )
                ),
                "currency": "INR",
                "receipt": f"gennzee_{order_id}"
            }
        )

        with db() as c:

            c.execute(
                """
                UPDATE web_orders
                SET razorpay_order_id=?
                WHERE id=?
                """,
                (
                    rp["id"],
                    order_id
                )
            )

            c.commit()

        return jsonify(rp)

    except Exception as e:
        return jsonify(
            error=str(e)
        ), 500


@app.post("/api/razorpay/verify")
@login_required
def razorpay_verify():

    data = request.get_json(force=True)

    order_id = int(data["order_id"])
    rp_order = data["razorpay_order_id"]
    rp_payment = data["razorpay_payment_id"]
    sig = data["razorpay_signature"]

    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        f"{rp_order}|{rp_payment}".encode(),
        hashlib.sha256
    ).hexdigest()

    if (
        not RAZORPAY_KEY_SECRET
        or not hmac.compare_digest(
            expected,
            sig
        )
    ):
        return jsonify(
            error="Payment signature verification failed."
        ), 400

    with db() as c:

        o = c.execute(
            """
            SELECT *
            FROM web_orders
            WHERE id=?
              AND user_id=?
            """,
            (
                order_id,
                session["user_id"]
            )
        ).fetchone()

        if not o or o["razorpay_order_id"] != rp_order:
            return jsonify(
                error="Order mismatch."
            ), 400

        rows = c.execute(
            """
            SELECT id, code
            FROM stock
            WHERE product_id=?
              AND sold=0
            ORDER BY id
            LIMIT ?
            """,
            (
                o["product_id"],
                o["quantity"]
            )
        ).fetchall()

        if len(rows) != o["quantity"]:

            c.execute(
                """
                UPDATE web_orders
                SET status='stock_error'
                WHERE id=?
                """,
                (order_id,)
            )

            c.commit()

            return jsonify(
                error="Stock became unavailable. Contact support."
            ), 409

        for s in rows:

            c.execute(
                """
                UPDATE stock
                SET sold=1
                WHERE id=? AND sold=0
                """,
                (s["id"],)
            )

            c.execute(
                """
                INSERT INTO web_order_items(
                    web_order_id,
                    stock_id,
                    code
                )
                VALUES(?,?,?)
                """,
                (
                    order_id,
                    s["id"],
                    s["code"]
                )
            )

        c.execute(
            """
            UPDATE web_orders
            SET
                status='delivered',
                razorpay_payment_id=?
            WHERE id=?
            """,
            (
                rp_payment,
                order_id
            )
        )

        c.commit()

    return jsonify(
        ok=True,
        redirect=url_for(
            "order",
            order_id=order_id
        )
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", "5000")
        )
    )
