import html
import hashlib
import hmac
import os
import secrets
import sqlite3
import smtplib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

import pandas as pd
import streamlit as st


# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "pharmacy.db"
CARDINAL_HEALTH_LOGIN_URL = (
    "https://pdlogin.cardinalhealth.com/signin?fromURI="
    "https%3A%2F%2Fvantus.cardinalhealth.com%2Fhome"
)


# --------------------------------------------------
# Authentication and authorization
# --------------------------------------------------

def get_app_setting(name, default=""):
    """Read a deployment secret or local environment setting without displaying it."""
    try:
        value = st.secrets.get(name, os.environ.get(name, default))
    except (FileNotFoundError, AttributeError):
        value = os.environ.get(name, default)
    return str(value).strip()


def hash_password(password, salt=None):
    """Create a salted PBKDF2 password hash; plaintext passwords are never stored."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return salt.hex(), digest.hex()


def password_is_valid(password):
    """Use a basic minimum standard for prototype user passwords."""
    return len(password) >= 12


def initialize_authentication():
    """Create local account and reset-token tables; safely upgrade the audit table."""
    with get_database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS app_users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Technician',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES app_users(user_id)
            )
            """
        )
        transaction_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(inventory_transactions)")
        }
        if transaction_columns and "performed_by" not in transaction_columns:
            connection.execute("ALTER TABLE inventory_transactions ADD COLUMN performed_by TEXT")


def bootstrap_admin_account():
    """Provision the deployment administrator from Secrets and keep its password in sync."""
    admin_email = get_app_setting("OTC_ADMIN_EMAIL").lower()
    admin_password = get_app_setting("OTC_ADMIN_PASSWORD")
    if not admin_email or not admin_password:
        return
    with get_database_connection() as connection:
        existing = connection.execute(
            "SELECT user_id, role FROM app_users WHERE email = ?", (admin_email,)
        ).fetchone()
        if existing is None:
            salt, password_hash = hash_password(admin_password)
            connection.execute(
                """
                INSERT INTO app_users (email, password_salt, password_hash, role)
                VALUES (?, ?, ?, 'Administrator')
                """,
                (admin_email, salt, password_hash),
            )
        elif existing[1] == "Administrator":
            # The deployment secret is the source of truth for the initial admin.
            # This also safely fixes a password changed in Streamlit Secrets.
            salt, password_hash = hash_password(admin_password)
            connection.execute(
                "UPDATE app_users SET password_salt = ?, password_hash = ? WHERE user_id = ?",
                (salt, password_hash, existing[0]),
            )


def authenticate_user(email, password):
    """Verify a user password and return safe identity information when valid."""
    with get_database_connection() as connection:
        row = connection.execute(
            """
            SELECT user_id, email, password_salt, password_hash, role, is_active
            FROM app_users WHERE email = ?
            """,
            (str(email).strip().lower(),),
        ).fetchone()
    if not row or not int(row[5]):
        return None
    _, password_hash = hash_password(password, bytes.fromhex(row[2]))
    if not hmac.compare_digest(password_hash, row[3]):
        return None
    return {"user_id": row[0], "email": row[1], "role": row[4]}


def create_app_user(email, password, role):
    """Allow an authenticated administrator to provision an identified staff account."""
    email = str(email).strip().lower()
    if "@" not in email:
        return False, "Enter a valid work email address."
    if not password_is_valid(password):
        return False, "Use a temporary password with at least 12 characters."
    salt, password_hash = hash_password(password)
    try:
        with get_database_connection() as connection:
            connection.execute(
                """
                INSERT INTO app_users (email, password_salt, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (email, salt, password_hash, role),
            )
        return True, f"Account created for {email}."
    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."


def create_reset_token(email):
    """Create a short-lived one-time reset token without revealing whether an account exists."""
    with get_database_connection() as connection:
        user = connection.execute(
            "SELECT user_id FROM app_users WHERE email = ? AND is_active = 1",
            (str(email).strip().lower(),),
        ).fetchone()
        if user is None:
            return None
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        connection.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (user[0], token_hash, expires_at),
        )
    return raw_token


def reset_password(email, raw_token, new_password):
    """Consume a valid reset token and securely replace the user's password hash."""
    if not password_is_valid(new_password):
        return False, "Use a password with at least 12 characters."
    token_hash = hashlib.sha256(str(raw_token).encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with get_database_connection() as connection:
        row = connection.execute(
            """
            SELECT prt.token_id, au.user_id
            FROM password_reset_tokens AS prt
            JOIN app_users AS au ON au.user_id = prt.user_id
            WHERE au.email = ? AND prt.token_hash = ?
              AND prt.used_at IS NULL AND prt.expires_at > ?
            ORDER BY prt.token_id DESC LIMIT 1
            """,
            (str(email).strip().lower(), token_hash, now),
        ).fetchone()
        if row is None:
            return False, "This reset link is invalid or has expired."
        salt, password_hash = hash_password(new_password)
        connection.execute(
            "UPDATE app_users SET password_salt = ?, password_hash = ? WHERE user_id = ?",
            (salt, password_hash, row[1]),
        )
        connection.execute(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_id = ?",
            (row[0],),
        )
    return True, "Your password has been reset. Please sign in."


def send_reset_email(email, raw_token):
    """Send a reset link only through configured organization-approved SMTP settings."""
    smtp_host = get_app_setting("OTC_SMTP_HOST")
    smtp_username = get_app_setting("OTC_SMTP_USERNAME")
    smtp_password = get_app_setting("OTC_SMTP_PASSWORD")
    app_url = get_app_setting("OTC_APP_URL")
    if not all([smtp_host, smtp_username, smtp_password, app_url]):
        return False

    reset_url = f"{app_url.rstrip('/')}?{urlencode({'reset_email': email, 'reset_token': raw_token})}"
    message = EmailMessage()
    message["Subject"] = "Smart OTC Assistant password reset"
    message["From"] = get_app_setting("OTC_SMTP_FROM", smtp_username)
    message["To"] = email
    message.set_content(
        "A password reset was requested for Smart OTC Assistant. "
        f"Use this link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )
    try:
        with smtplib.SMTP_SSL(smtp_host, int(get_app_setting("OTC_SMTP_PORT", "465"))) as server:
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        return False


# --------------------------------------------------
# Database connection and inventory search
# --------------------------------------------------

def get_database_connection():
    """Open the local prototype database."""
    return sqlite3.connect(DATABASE_FILE)


def initialize_search_log():
    """Create local usage tables without storing the text users enter."""
    with get_database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS search_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                pharmacy_code TEXT NOT NULL,
                searched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                result_count INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS search_event_products (
                event_id INTEGER NOT NULL,
                product_id TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES search_events(event_id)
            )
            """
        )


def initialize_inventory_log():
    """Create a local audit log for test inventory adjustments."""
    with get_database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS inventory_transactions (
                transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT NOT NULL,
                pharmacy_code TEXT NOT NULL,
                transaction_type TEXT NOT NULL,
                quantity_change INTEGER NOT NULL,
                quantity_before INTEGER NOT NULL,
                quantity_after INTEGER NOT NULL,
                notes TEXT,
                performed_by TEXT,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def find_product_by_barcode(barcode, pharmacy_code):
    """Find a catalog product and its selected-pharmacy inventory, if present."""
    query = """
        SELECT
            p.Product_ID,
            p.Brand_Name,
            p.Generic_Name,
            p.Category,
            p.Strength,
            p.Form,
            p.Location AS Product_Location,
            p.Barcode,
            i.location AS Inventory_Location,
            i.quantity,
            i.reorder_level
        FROM products AS p
        LEFT JOIN inventory AS i
          ON p.Product_ID = i.product_id AND i.pharmacy_code = ?
        WHERE TRIM(CAST(p.Barcode AS TEXT)) = TRIM(?)
        LIMIT 1
    """
    with get_database_connection() as connection:
        return pd.read_sql_query(query, connection, params=(str(pharmacy_code), str(barcode)))


def adjust_inventory(barcode, pharmacy_code, quantity_change, transaction_type, performed_by, notes="", location="", reorder_level=0):
    """Add or remove stock and write an audit entry; inventory never goes below zero."""
    product = find_product_by_barcode(barcode, pharmacy_code)
    if product.empty:
        return False, "No OTC product matches this barcode. Use Add New OTC Product first."

    product_row = product.iloc[0]
    product_id = str(product_row["Product_ID"])
    quantity_change = int(quantity_change)
    if quantity_change == 0:
        return False, "Enter a quantity greater than zero."

    with get_database_connection() as connection:
        existing = connection.execute(
            """
            SELECT quantity, reorder_level, location
            FROM inventory
            WHERE product_id = ? AND pharmacy_code = ?
            """,
            (product_id, str(pharmacy_code)),
        ).fetchone()

        if existing is None:
            if quantity_change < 0:
                return False, "This product has no inventory record for the selected pharmacy."
            quantity_before = 0
            quantity_after = quantity_change
            inventory_location = str(location).strip() or display_value(
                product_row["Product_Location"], fallback="Location not listed"
            )
            connection.execute(
                """
                INSERT INTO inventory (
                    product_id, pharmacy_code, location, quantity, reorder_level, last_updated
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    product_id,
                    str(pharmacy_code),
                    inventory_location,
                    quantity_after,
                    int(reorder_level),
                ),
            )
        else:
            quantity_before = int(existing[0] or 0)
            quantity_after = quantity_before + quantity_change
            if quantity_after < 0:
                return False, f"Cannot remove {abs(quantity_change)}. Only {quantity_before} are on hand."
            connection.execute(
                """
                UPDATE inventory
                SET quantity = ?, last_updated = CURRENT_TIMESTAMP
                WHERE product_id = ? AND pharmacy_code = ?
                """,
                (quantity_after, product_id, str(pharmacy_code)),
            )

        connection.execute(
            """
            INSERT INTO inventory_transactions (
                product_id, pharmacy_code, transaction_type, quantity_change,
                quantity_before, quantity_after, notes, performed_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                product_id,
                str(pharmacy_code),
                transaction_type,
                quantity_change,
                quantity_before,
                quantity_after,
                str(notes).strip() or None,
                str(performed_by).strip(),
            ),
        )
    return True, f"{display_value(product_row['Brand_Name'])}: on-hand quantity is now {quantity_after}."


def get_next_product_id(connection):
    """Generate the next readable test product ID, such as OTC009."""
    rows = connection.execute("SELECT Product_ID FROM products").fetchall()
    highest = 0
    for (product_id,) in rows:
        text_id = str(product_id)
        if text_id.upper().startswith("OTC") and text_id[3:].isdigit():
            highest = max(highest, int(text_id[3:]))
    return f"OTC{highest + 1:03d}"


def add_new_otc_product(
    barcode,
    brand_name,
    generic_name,
    category,
    strength,
    dosage_form,
    location,
    reorder_level,
    initial_quantity,
    pharmacy_code,
    performed_by,
):
    """Add a test OTC product and its first inventory record for one pharmacy."""
    required_values = [barcode, brand_name, category, dosage_form, location]
    if not all(str(value).strip() for value in required_values):
        return False, "Barcode, brand name, category, form, and shelf location are required."
    if int(initial_quantity) < 0 or int(reorder_level) < 0:
        return False, "Quantity and reorder level cannot be negative."

    with get_database_connection() as connection:
        existing = connection.execute(
            "SELECT 1 FROM products WHERE TRIM(CAST(Barcode AS TEXT)) = TRIM(?)",
            (str(barcode),),
        ).fetchone()
        if existing:
            return False, "A product with this barcode already exists. Use Receive Stock instead."

        product_id = get_next_product_id(connection)
        connection.execute(
            """
            INSERT INTO products (
                Product_ID, Brand_Name, Generic_Name, Category, Strength, Form,
                Location, Manufacturer, Barcode
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                product_id,
                str(brand_name).strip(),
                str(generic_name).strip(),
                str(category).strip(),
                str(strength).strip(),
                str(dosage_form).strip(),
                str(location).strip(),
                "Not listed",
                str(barcode).strip(),
            ),
        )
        connection.execute(
            """
            INSERT INTO inventory (
                product_id, pharmacy_code, location, quantity, reorder_level, last_updated
            )
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                product_id,
                str(pharmacy_code),
                str(location).strip(),
                int(initial_quantity),
                int(reorder_level),
            ),
        )
        connection.execute(
            """
            INSERT INTO inventory_transactions (
                product_id, pharmacy_code, transaction_type, quantity_change,
                quantity_before, quantity_after, notes, performed_by
            )
            VALUES (?, ?, 'New Product', ?, 0, ?, 'Initial inventory', ?)
            """,
            (
                product_id,
                str(pharmacy_code),
                int(initial_quantity),
                int(initial_quantity),
                str(performed_by).strip(),
            ),
        )
    return True, f"{brand_name} was added as {product_id} for Pharmacy {pharmacy_code}."


def get_recent_inventory_transactions(pharmacy_code, limit=10):
    """Return recent local adjustments for supervisor review."""
    query = """
        SELECT
            transaction_type AS Action,
            p.Brand_Name AS Brand,
            quantity_change AS Change,
            quantity_before AS "Before",
            quantity_after AS "After",
            notes AS Notes,
            performed_by AS "Edited By",
            recorded_at AS "Recorded At"
        FROM inventory_transactions AS it
        JOIN products AS p ON p.Product_ID = it.product_id
        WHERE it.pharmacy_code = ?
        ORDER BY it.transaction_id DESC
        LIMIT ?
    """
    with get_database_connection() as connection:
        return pd.read_sql_query(query, connection, params=(str(pharmacy_code), int(limit)))


def record_search_event(pharmacy_code, results):
    """Record one submitted search and its matching products, never its raw text."""
    with get_database_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO search_events (pharmacy_code, result_count) VALUES (?, ?)",
            (str(pharmacy_code), int(len(results))),
        )
        event_id = cursor.lastrowid
        product_ids = []
        if not results.empty:
            for product_id in results["Product_ID"].drop_duplicates():
                if hasattr(product_id, "item"):
                    product_id = product_id.item()
                product_ids.append((event_id, str(product_id)))
        connection.executemany(
            "INSERT INTO search_event_products (event_id, product_id) VALUES (?, ?)",
            product_ids,
        )
    return event_id


def get_search_usage(pharmacy_code, limit=5):
    """Return total submitted searches and the most frequently found products."""
    with get_database_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM search_events WHERE pharmacy_code = ?",
            (str(pharmacy_code),),
        ).fetchone()[0]
        popular = pd.read_sql_query(
            """
            SELECT p.Brand_Name, COUNT(*) AS Search_Count
            FROM search_event_products AS sep
            JOIN search_events AS se ON se.event_id = sep.event_id
            JOIN products AS p ON CAST(p.Product_ID AS TEXT) = sep.product_id
            WHERE se.pharmacy_code = ?
            GROUP BY p.Product_ID, p.Brand_Name
            ORDER BY Search_Count DESC, p.Brand_Name COLLATE NOCASE
            LIMIT ?
            """,
            connection,
            params=(str(pharmacy_code), int(limit)),
        )
    return int(total), popular


def get_product_categories():
    """Return the categories stored in the local product catalog."""
    query = """
        SELECT DISTINCT Category
        FROM products
        WHERE Category IS NOT NULL AND TRIM(Category) <> ''
        ORDER BY Category COLLATE NOCASE
    """
    with get_database_connection() as connection:
        categories = pd.read_sql_query(query, connection)["Category"]
    return categories.astype(str).tolist()


def search_inventory(search_term, pharmacy_code, category=None):
    """Find products by brand, generic name, or barcode, with an optional category filter."""
    query = """
        SELECT
            p.Product_ID,
            p.Brand_Name,
            p.Generic_Name,
            p.Category,
            p.Strength,
            p.Form,
            p.Location AS Product_Location,
            p.Manufacturer,
            p.Barcode,
            i.pharmacy_code,
            i.location AS Inventory_Location,
            i.quantity,
            i.reorder_level,
            i.last_updated
        FROM products AS p
        JOIN inventory AS i ON p.Product_ID = i.product_id
        WHERE i.pharmacy_code = ?
          AND (
              p.Brand_Name LIKE ?
              OR p.Generic_Name LIKE ?
              OR p.Barcode LIKE ?
          )
          AND (? IS NULL OR p.Category = ?)
        ORDER BY p.Brand_Name COLLATE NOCASE
    """

    search_pattern = f"%{search_term.strip()}%"
    with get_database_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(
                pharmacy_code,
                search_pattern,
                search_pattern,
                search_pattern,
                category,
                category,
            ),
        )


def get_reorder_review(pharmacy_code):
    """Return products at or below their reorder level for staff review."""
    query = """
        SELECT
            p.Product_ID,
            p.Brand_Name,
            p.Generic_Name,
            p.Category,
            p.Strength,
            p.Form,
            i.location AS Inventory_Location,
            i.quantity,
            i.reorder_level,
            i.last_updated
        FROM products AS p
        JOIN inventory AS i ON p.Product_ID = i.product_id
        WHERE i.pharmacy_code = ?
          AND i.quantity <= i.reorder_level
        ORDER BY
            CASE WHEN i.quantity <= 0 THEN 0 ELSE 1 END,
            p.Brand_Name COLLATE NOCASE
    """
    with get_database_connection() as connection:
        review = pd.read_sql_query(query, connection, params=(str(pharmacy_code),))

    if not review.empty:
        review["Stock_Status"] = review.apply(
            lambda row: get_stock_status(row["quantity"], row["reorder_level"])[0],
            axis=1,
        )
    return review


def find_related_products(product_id, category, pharmacy_code, limit=3):
    """Return other in-stock-catalog items in the same category for context."""
    if pd.isna(category) or not str(category).strip():
        return pd.DataFrame()
    # Product IDs may be text values such as "OTC005" or numeric IDs.
    if hasattr(product_id, "item"):
        product_id = product_id.item()

    query = """
        SELECT
            p.Product_ID,
            p.Brand_Name,
            p.Generic_Name,
            p.Strength,
            p.Form,
            i.location AS Inventory_Location,
            i.quantity,
            i.reorder_level
        FROM products AS p
        JOIN inventory AS i ON p.Product_ID = i.product_id
        WHERE i.pharmacy_code = ?
          AND p.Category = ?
          AND p.Product_ID <> ?
        ORDER BY p.Brand_Name COLLATE NOCASE
        LIMIT ?
    """
    with get_database_connection() as connection:
        return pd.read_sql_query(
            query,
            connection,
            params=(pharmacy_code, category, product_id, int(limit)),
        )


def display_value(value, fallback="Not listed"):
    """Return a readable value for optional database fields."""
    if pd.isna(value) or str(value).strip() == "":
        return fallback
    return str(value).strip()


def get_stock_status(quantity, reorder_level):
    """Return a label and CSS class for the inventory quantity."""
    quantity = int(quantity or 0)
    reorder_level = int(reorder_level or 0)

    if quantity <= 0:
        return "Out of Stock", "out"
    if quantity <= reorder_level:
        return "Low Stock", "low"
    return "Available", "available"


def render_reorder_review(pharmacy_code):
    """Show low-stock items for the selected pharmacy; this never creates orders."""
    st.subheader("Low Stock & Reorder Review")
    st.caption(
        "Review queue only — no automatic order is created or sent to any supplier."
    )

    review = get_reorder_review(pharmacy_code)
    if review.empty:
        st.success("No low-stock or out-of-stock products are listed for this pharmacy.")
        return

    out_of_stock = int((review["Stock_Status"] == "Out of Stock").sum())
    low_stock = int((review["Stock_Status"] == "Low Stock").sum())
    out_column, low_column = st.columns(2)
    out_column.metric("Out of Stock", out_of_stock)
    low_column.metric("Low Stock", low_stock)

    st.warning(
        "Review these items before placing an order through the approved pharmacy process."
    )
    review_table = review[
        [
            "Brand_Name",
            "Generic_Name",
            "Category",
            "Inventory_Location",
            "quantity",
            "reorder_level",
            "Stock_Status",
            "last_updated",
        ]
    ].rename(
        columns={
            "Brand_Name": "Brand",
            "Generic_Name": "Generic",
            "Category": "Category",
            "Inventory_Location": "Location",
            "quantity": "On Hand",
            "reorder_level": "Reorder Level",
            "Stock_Status": "Status",
            "last_updated": "Last Updated",
        }
    )
    st.dataframe(review_table, hide_index=True, use_container_width=True)


def render_inventory_update(pharmacy_code):
    """Render the test-only receive/remove workflow for barcode or keyboard entry."""
    st.subheader("Stock Actions")
    st.caption(
        "Test-data workflow for authorized staff. A USB barcode scanner can enter the barcode in the same field as a keyboard."
    )

    flash_message = st.session_state.pop("inventory_update_message", None)
    if flash_message:
        st.success(flash_message)

    current_user = st.session_state["current_user"]
    st.caption(f"Signed in as: {current_user['email']} ({current_user['role']})")

    action = st.radio(
        "Select inventory action",
        ["Receive Stock", "Remove Stock"],
        horizontal=True,
        key="inventory_action",
    )
    with st.form("inventory_adjustment_form", clear_on_submit=True):
        barcode = st.text_input(
            "Scan or enter barcode",
            placeholder="Click here, then scan or type the barcode",
        )
        quantity = st.number_input("Quantity", min_value=1, step=1)
        notes = st.text_input(
            "Notes (optional)",
            placeholder="Example: received shipment or shelf count correction",
        )

        location = ""
        reorder_level = 0
        if action == "Receive Stock":
            st.caption(
                "Shelf location and reorder level are used only when this product is not yet listed for the selected pharmacy."
            )
            location = st.text_input("Shelf location for a new pharmacy record (optional)")
            reorder_level = st.number_input(
                "Reorder level for a new pharmacy record", min_value=0, step=1
            )

        submitted = st.form_submit_button(action)

    if submitted:
        if not barcode.strip():
            st.error("Scan or enter a barcode first.")
        else:
            change = int(quantity) if action == "Receive Stock" else -int(quantity)
            transaction_type = "Receive Stock" if change > 0 else "Remove Stock"
            success, message = adjust_inventory(
                barcode=barcode,
                pharmacy_code=pharmacy_code,
                quantity_change=change,
                transaction_type=transaction_type,
                performed_by=current_user["email"],
                notes=notes,
                location=location,
                reorder_level=reorder_level,
            )
            if success:
                st.session_state["inventory_update_message"] = message
                st.rerun()
            st.error(message)

    with st.expander("Add New OTC Product"):
        st.caption(
            "Use this only when the scanned barcode is not already in the test catalog."
        )
        with st.form("new_otc_product_form", clear_on_submit=True):
            new_barcode = st.text_input("Barcode", key="new_product_barcode")
            new_brand = st.text_input("Brand name")
            new_generic = st.text_input("Generic name (optional)")
            new_category = st.text_input("Category")
            new_strength = st.text_input("Strength (optional)")
            new_form = st.text_input("Form", placeholder="Example: Tablet, Liquid, Cream")
            new_location = st.text_input("Shelf location")
            new_reorder_level = st.number_input("Reorder level", min_value=0, step=1)
            new_initial_quantity = st.number_input("Initial quantity", min_value=0, step=1)
            add_submitted = st.form_submit_button("Add New OTC Product")

        if add_submitted:
            success, message = add_new_otc_product(
                barcode=new_barcode,
                brand_name=new_brand,
                generic_name=new_generic,
                category=new_category,
                strength=new_strength,
                dosage_form=new_form,
                location=new_location,
                reorder_level=new_reorder_level,
                initial_quantity=new_initial_quantity,
                pharmacy_code=pharmacy_code,
                performed_by=current_user["email"],
            )
            if success:
                st.session_state["inventory_update_message"] = message
                st.rerun()
            st.error(message)

    with st.expander("Recent Inventory Changes"):
        history = get_recent_inventory_transactions(pharmacy_code)
        if history.empty:
            st.caption("No inventory changes have been recorded for this pharmacy yet.")
        else:
            st.dataframe(history, hide_index=True, use_container_width=True)


def render_product_card(row):
    """Render a compact, readable inventory result card."""
    quantity = int(row["quantity"] or 0)
    reorder_level = int(row["reorder_level"] or 0)
    status, status_class = get_stock_status(quantity, reorder_level)

    brand = html.escape(display_value(row["Brand_Name"]))
    generic = html.escape(display_value(row["Generic_Name"]))
    category = html.escape(display_value(row["Category"]))
    strength = html.escape(display_value(row["Strength"]))
    dosage_form = html.escape(display_value(row["Form"]))
    pharmacy = html.escape(display_value(row["pharmacy_code"]))
    location = html.escape(
        display_value(row["Inventory_Location"], fallback="Location not listed")
    )
    barcode = html.escape(display_value(row["Barcode"]))
    last_updated = html.escape(display_value(row["last_updated"]))

    st.markdown(
        f"""
        <section class="product-card">
          <div class="card-heading">
            <div>
              <div class="eyebrow">OTC PRODUCT</div>
              <h3>{brand}</h3>
              <div class="generic-name">{generic}</div>
            </div>
            <span class="stock-badge {status_class}">{status}</span>
          </div>
          <div class="product-tags">
            <span>{strength}</span><span>{dosage_form}</span><span>{category}</span>
          </div>
          <div class="inventory-grid">
            <div class="inventory-item location-item">
              <span class="item-label">SHELF LOCATION</span>
              <strong>{location}</strong>
            </div>
            <div class="inventory-item">
              <span class="item-label">ON HAND</span>
              <strong>{quantity}</strong>
            </div>
            <div class="inventory-item">
              <span class="item-label">REORDER AT</span>
              <strong>{reorder_level}</strong>
            </div>
          </div>
          <div class="card-footer">
            <span>Pharmacy {pharmacy}</span>
            <span>Barcode: {barcode}</span>
          </div>
          <div class="updated-line">Last updated: {last_updated}</div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def render_related_products(row):
    """Show other products in the same category without recommending a substitute."""
    related = find_related_products(
        row["Product_ID"], row["Category"], row["pharmacy_code"]
    )
    if related.empty:
        return

    st.markdown("**Related products in the same category**")
    st.caption("For information only. This list does not recommend a product substitution.")
    for _, item in related.iterrows():
        name = html.escape(display_value(item["Brand_Name"]))
        strength = html.escape(display_value(item["Strength"]))
        dosage_form = html.escape(display_value(item["Form"]))
        location = html.escape(
            display_value(item["Inventory_Location"], fallback="Location not listed")
        )
        quantity = int(item["quantity"] or 0)
        status, _ = get_stock_status(quantity, item["reorder_level"])
        st.markdown(
            f"- **{name}** — {strength}, {dosage_form}; "
            f"{location}; {quantity} on hand ({status})"
        )


def get_user_count():
    with get_database_connection() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM app_users").fetchone()[0])


def render_login_gate():
    """Show sign-in and password-reset controls before any inventory data is displayed."""
    st.title("💊 Smart OTC Assistant")
    st.caption("Secure OTC Inventory Access")

    query_params = st.query_params
    reset_email = str(query_params.get("reset_email", "")).strip().lower()
    reset_token = str(query_params.get("reset_token", "")).strip()

    if reset_email and reset_token:
        st.subheader("Reset your password")
        with st.form("complete_password_reset"):
            new_password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            reset_submitted = st.form_submit_button("Reset password")
        if reset_submitted:
            if new_password != confirm_password:
                st.error("The passwords do not match.")
            else:
                success, message = reset_password(reset_email, reset_token, new_password)
                if success:
                    st.query_params.clear()
                    st.success(message)
                else:
                    st.error(message)
        st.stop()

    if get_user_count() == 0:
        st.warning("Secure access has not been configured yet.")
        st.info(
            "Before using this app, an administrator must set OTC_ADMIN_EMAIL and OTC_ADMIN_PASSWORD "
            "in the Streamlit Secrets or local environment, then restart the app."
        )
        st.stop()

    login_tab, forgot_tab = st.tabs(["Sign in", "Forgot password?"])
    with login_tab:
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="name@organization.org")
            password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Sign in", type="primary")
        if login_submitted:
            user = authenticate_user(email, password)
            if user:
                st.session_state["current_user"] = user
                st.rerun()
            st.error("The email or password is incorrect.")

    with forgot_tab:
        st.caption("Enter your work email to receive a one-time reset link.")
        with st.form("forgot_password_form"):
            reset_request_email = st.text_input("Work email", key="reset_request_email")
            forgot_submitted = st.form_submit_button("Send reset link")
        if forgot_submitted:
            raw_token = create_reset_token(reset_request_email)
            email_sent = raw_token and send_reset_email(reset_request_email, raw_token)
            if email_sent:
                st.success("If that email is registered, a password-reset link has been sent.")
            else:
                st.info(
                    "If that email is registered, contact the app administrator for password-reset assistance."
                )

    st.stop()


def render_user_management():
    """Administrator-only account provisioning for the local prototype."""
    st.header("User Management")
    st.caption("Create identified accounts for authorized pharmacy staff.")
    with st.form("create_user_form", clear_on_submit=True):
        email = st.text_input("Staff work email", placeholder="name@organization.org")
        temporary_password = st.text_input(
            "Temporary password", type="password", help="At least 12 characters."
        )
        role = st.selectbox(
            "Role",
            ["Technician", "Pharmacist", "Supervisor", "Manager", "Administrator"],
        )
        create_submitted = st.form_submit_button("Create staff account", type="primary")
    if create_submitted:
        success, message = create_app_user(email, temporary_password, role)
        if success:
            st.success(message)
        else:
            st.error(message)

    with get_database_connection() as connection:
        users = pd.read_sql_query(
            "SELECT email AS Email, role AS Role, created_at AS 'Created At' "
            "FROM app_users WHERE is_active = 1 ORDER BY email COLLATE NOCASE",
            connection,
        )
    st.dataframe(users, hide_index=True, use_container_width=True)


# --------------------------------------------------
# Page configuration and styling
# --------------------------------------------------

st.set_page_config(
    page_title="Smart OTC Assistant",
    page_icon="💊",
    layout="centered",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 900px; padding-top: 2.2rem; padding-bottom: 3rem;}
      .product-card {
        border: 1px solid #e4e8ef; border-radius: 16px; padding: 1.25rem 1.4rem;
        margin: 1rem 0 1.2rem; background: linear-gradient(145deg, #ffffff, #fbfcfe);
        box-shadow: 0 5px 18px rgba(20, 35, 60, .06);
      }
      .card-heading {display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;}
      .eyebrow {font-size:.68rem; font-weight:700; letter-spacing:.11em; color:#728096; margin-bottom:.25rem;}
      .product-card h3 {font-size:1.35rem; margin:0; color:#19283d;}
      .generic-name {font-size:.95rem; color:#657187; margin-top:.2rem;}
      .stock-badge {white-space:nowrap; border-radius:999px; padding:.42rem .75rem; font-size:.82rem; font-weight:700;}
      .stock-badge.available {color:#176b45; background:#e7f6ed;}
      .stock-badge.low {color:#8a5200; background:#fff2d8;}
      .stock-badge.out {color:#a42c33; background:#fde9e9;}
      .product-tags {display:flex; flex-wrap:wrap; gap:.45rem; margin:1rem 0;}
      .product-tags span {background:#f0f3f8; color:#42516a; padding:.28rem .58rem; border-radius:7px; font-size:.8rem;}
      .inventory-grid {display:grid; grid-template-columns:2fr 1fr 1fr; gap:.65rem;}
      .inventory-item {background:#f7f9fc; border-radius:10px; padding:.75rem .85rem; min-width:0;}
      .item-label {display:block; font-size:.66rem; letter-spacing:.08em; font-weight:700; color:#758197; margin-bottom:.3rem;}
      .inventory-item strong {font-size:1rem; color:#23334c; overflow-wrap:anywhere;}
      .card-footer {display:flex; flex-wrap:wrap; justify-content:space-between; gap:.5rem; margin-top:1rem; color:#59677c; font-size:.8rem;}
      .updated-line {margin-top:.45rem; color:#8a94a5; font-size:.73rem;}
      @media (max-width:560px) {
        .product-card {padding:1rem;}
        .card-heading {flex-direction:column;}
        .inventory-grid {grid-template-columns:1fr 1fr;}
        .location-item {grid-column:1 / -1;}
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Application header and page navigation
# --------------------------------------------------

try:
    initialize_inventory_log()
    initialize_authentication()
    bootstrap_admin_account()
except sqlite3.Error as error:
    st.error("The local authentication database could not be prepared.")
    st.caption(f"Database details: {error}")
    st.stop()

if "current_user" not in st.session_state:
    render_login_gate()

if "dark_mode" not in st.session_state:
    st.session_state["dark_mode"] = False
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "lookup"

st.title("💊 Smart OTC Assistant")
st.caption("OTC Inventory Lookup — Technician Prototype")

theme_button_label = (
    "☀️ Switch to Light Mode"
    if st.session_state["dark_mode"]
    else "🌙 Switch to Dark Mode"
)

if st.session_state["dark_mode"]:
    st.markdown(
        """
        <style>
          [data-testid="stAppViewContainer"], [data-testid="stHeader"] {background:#111827; color:#e5e7eb;}
          [data-testid="stAppViewContainer"] h1, [data-testid="stAppViewContainer"] h2,
          [data-testid="stAppViewContainer"] h3, [data-testid="stAppViewContainer"] p,
          [data-testid="stAppViewContainer"] label, [data-testid="stAppViewContainer"] span {color:#e5e7eb;}
          [data-testid="stCaptionContainer"] p {color:#aab7cc !important;}
          .product-card {border-color:#334155; background:linear-gradient(145deg, #1e293b, #172033); box-shadow:none;}
          .product-card h3, .inventory-item strong {color:#f8fafc;}
          .eyebrow, .generic-name, .item-label, .card-footer, .updated-line {color:#b6c2d3;}
          .product-tags span {background:#334155; color:#e5e7eb;}
          .inventory-item {background:#263449;}
          div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {background:#1e293b; color:#f8fafc; border-color:#475569;}
          input {color:#f8fafc !important;}
          [data-testid="stDataFrame"] {border-color:#475569;}
        </style>
        """,
        unsafe_allow_html=True,
    )

st.divider()


# --------------------------------------------------
# Main workspace and right-side action panel
# --------------------------------------------------

workspace_column, action_column = st.columns([4.4, 1.6], gap="large")

with action_column:
    st.markdown("#### Quick Actions")
    st.caption(f"Signed in: {st.session_state['current_user']['email']}")
    if st.button(theme_button_label, key="theme_toggle_button", use_container_width=True):
        st.session_state["dark_mode"] = not st.session_state["dark_mode"]
        st.rerun()

    if st.session_state["current_page"] == "lookup":
        if st.button("📦 Inventory Update", type="primary", use_container_width=True):
            st.session_state["current_page"] = "inventory"
            st.rerun()
    else:
        if st.button("← Back to Search", use_container_width=True):
            st.session_state["current_page"] = "lookup"
            st.rerun()

    if st.session_state["current_user"]["role"] == "Administrator":
        if st.button("👤 Manage Users", use_container_width=True):
            st.session_state["current_page"] = "users"
            st.rerun()

    st.link_button(
        "Open Cardinal Health ↗",
        CARDINAL_HEALTH_LOGIN_URL,
        use_container_width=True,
    )
    st.caption("Authorized users only. No login details or orders are stored in this app.")
    if st.button("Sign out", use_container_width=True):
        st.session_state.pop("current_user", None)
        st.rerun()

with workspace_column:
    st.subheader("Pharmacy")
    pharmacy_options = ["001", "002", "003", "004"]
    pharmacy_code = st.selectbox(
        "Select Pharmacy",
        pharmacy_options,
        index=pharmacy_options.index("004"),
    )
    st.caption(f"Current prototype pharmacy: {pharmacy_code}")

    if st.session_state["current_page"] == "inventory":
        st.divider()
        st.header("Inventory Update")
        st.caption(
            "Use this separate workspace to receive stock, remove stock, add a new OTC product, or review recent inventory changes."
        )
        try:
            initialize_inventory_log()
            render_inventory_update(pharmacy_code)
        except (sqlite3.Error, pd.errors.DatabaseError) as error:
            st.error("The local inventory database could not be read for the inventory tools.")
            st.caption(f"Database details: {error}")
    elif st.session_state["current_page"] == "users":
        st.divider()
        render_user_management()
    else:
        try:
            initialize_inventory_log()
            render_reorder_review(pharmacy_code)
        except (sqlite3.Error, pd.errors.DatabaseError) as error:
            st.error("The local inventory database could not be read for the inventory tools.")
            st.caption(f"Database details: {error}")

        st.divider()
        st.subheader("OTC Product Search")
        categories = get_product_categories()
        initialize_search_log()
        with st.form("otc_search_form"):
            selected_category = st.selectbox(
                "Filter by category",
                ["All categories", *categories],
            )
            search = st.text_input(
                "Search by brand name, generic name, or barcode (optional)",
                placeholder="Example: Tylenol, Acetaminophen, or barcode",
            )
            submitted = st.form_submit_button("Search")

    if st.session_state["current_page"] == "lookup":
        if submitted:
            st.session_state["search_done"] = False
            try:
                if not search.strip() and selected_category == "All categories":
                    st.warning("Enter a search term or choose a category first.")
                else:
                    category_filter = (
                        None if selected_category == "All categories" else selected_category
                    )
                    results = search_inventory(search, pharmacy_code, category_filter)
                    record_search_event(pharmacy_code, results)
                    st.session_state["search_results"] = results
                    st.session_state["search_pharmacy"] = pharmacy_code
                    st.session_state["search_done"] = True
            except (sqlite3.Error, pd.errors.DatabaseError) as error:
                st.error("The local inventory database could not be read. Check that the database file and tables are in place.")
                st.caption(f"Database details: {error}")

        if st.session_state.get("search_done"):
            if st.session_state.get("search_pharmacy") == pharmacy_code:
                results = st.session_state["search_results"]
                if not results.empty:
                    st.success(f"{len(results)} product(s) found")
                    for _, product in results.iterrows():
                        render_product_card(product)
                        render_related_products(product)
                elif not submitted:
                    st.warning("No product found. Try another search or category.")
        else:
            st.info("Choose a category or enter a product name or barcode, then select Search.")

        with st.expander("Search usage summary"):
            try:
                total_searches, popular_products = get_search_usage(pharmacy_code)
                st.metric("Submitted searches", total_searches)
                if not popular_products.empty:
                    st.caption("Most frequently found products")
                    st.dataframe(popular_products, hide_index=True, use_container_width=True)
                else:
                    st.caption("No matching products have been logged yet.")
            except sqlite3.Error as error:
                st.error(f"Could not read the local search summary: {error}")
