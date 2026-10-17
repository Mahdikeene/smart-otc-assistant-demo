import html
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "pharmacy.db"


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
# Application header
# --------------------------------------------------

st.title("💊 Smart OTC Assistant")
st.caption("OTC Inventory Lookup — Technician Prototype")
st.divider()


# --------------------------------------------------
# Pharmacy and search controls
# --------------------------------------------------

st.subheader("Pharmacy")
pharmacy_code = st.selectbox("Select Pharmacy", ["004"])
st.caption(f"Current prototype pharmacy: {pharmacy_code}")

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


# --------------------------------------------------
# Search results
# --------------------------------------------------

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
