from __future__ import annotations

import json
import os
import threading
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, abort, g, jsonify, request, send_from_directory
from flask_socketio import SocketIO
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

APP_ROOT = Path(__file__).resolve().parent
DATA_FILE = APP_ROOT / "orders.json"

SECRET_KEY = os.environ.get("CAFE_SECRET_KEY", "change-me")
ADMIN_PASSWORD = os.environ.get("CAFE_ADMIN_PASSWORD", "admin123")
SCREEN_PASSWORD = os.environ.get("CAFE_SCREEN_PASSWORD", "screen123")
TOKEN_MAX_AGE = int(os.environ.get("CAFE_TOKEN_MAX_AGE", 60 * 60 * 24))
ALLOWED_STATUSES = {"new", "in_progress", "ready", "done"}

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
# Використовуємо eventlet для кращої продуктивності WebSocket в production
try:
    import eventlet
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
except ImportError:
    # Якщо eventlet не встановлений, використовуємо threading
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
_lock = threading.Lock()
_orders: List[Dict[str, Any]] = []
_last_number = 0
serializer = URLSafeTimedSerializer(SECRET_KEY)


def _load_orders_from_disk() -> None:
    global _orders, _last_number
    _orders = []
    _last_number = 0
    if not DATA_FILE.exists():
        return

    try:
        with DATA_FILE.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
            if isinstance(data, dict):
                maybe_orders = data.get("orders")
                if isinstance(maybe_orders, list):
                    _orders = maybe_orders
                _last_number = int(data.get("lastNumber") or 0)
            elif isinstance(data, list):
                _orders = data
                if _orders:
                    _last_number = max((order.get("number") or 0) for order in _orders)
    except Exception:
        _orders = []
        _last_number = 0


def _save_orders_to_disk() -> None:
    payload = {
        "orders": _orders,
        "lastNumber": max(
            _last_number,
            max((order.get("number") or 0) for order in _orders) if _orders else 0,
        ),
    }
    DATA_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _get_next_number() -> int:
    global _last_number
    _last_number = (_last_number or 0) + 1
    return _last_number


def _find_order(order_id: str) -> Dict[str, Any] | None:
    for order in _orders:
        if order.get("id") == order_id:
            return order
    return None


_load_orders_from_disk()


def _broadcast_orders() -> None:
    socketio.emit("orders_updated", _orders)


def _sanitize_money(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        number = round(float(value), 2)
    except (TypeError, ValueError):
        return None
    if number < 0:
        return None
    return number


def _normalize_items(items_payload: Any) -> tuple[list[dict[str, Any]], float]:
    if not isinstance(items_payload, list):
        return [], 0.0

    normalized: list[dict[str, Any]] = []
    total = 0.0
    for raw in items_payload:
        if not isinstance(raw, dict):
            continue
        label = str(raw.get("label") or "").strip()
        if not label:
            continue
        try:
            quantity = int(raw.get("quantity") or 0)
        except (TypeError, ValueError):
            quantity = 0
        unit_price = _sanitize_money(raw.get("unitPrice"))
        if quantity <= 0 or unit_price is None:
            continue
        line_total = round(unit_price * quantity, 2)
        total += line_total
        normalized.append(
            {
                "key": raw.get("key"),
                "label": label,
                "quantity": quantity,
                "unitPrice": unit_price,
                "lineTotal": line_total,
                "isManual": bool(raw.get("isManual")),
            }
        )
    return normalized, round(total, 2)


def _apply_status_transition(order: Dict[str, Any], new_status: str) -> None:
    now_ms = int(time.time() * 1000)
    if new_status == "new":
        order.pop("inProgressAt", None)
        order.pop("readyAt", None)
        order.pop("doneAt", None)
    elif new_status == "in_progress":
        order["inProgressAt"] = now_ms
        order.pop("readyAt", None)
        order.pop("doneAt", None)
    elif new_status == "ready":
        order.setdefault("inProgressAt", order.get("inProgressAt") or now_ms)
        order["readyAt"] = now_ms
        order.pop("doneAt", None)
    elif new_status == "done":
        order.setdefault("readyAt", order.get("readyAt") or now_ms)
        order["doneAt"] = now_ms


def _generate_token(role: str) -> str:
    return serializer.dumps({"role": role})


def _verify_token(token: str) -> str | None:
    if not token:
        return None
    try:
        data = serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("role")


def _auth_error(message: str, status: int = 401):
    return jsonify({"error": message}), status


def authenticate_request() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    token = auth_header[len(prefix) :].strip()
    return _verify_token(token)


def require_role(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            role = authenticate_request()
            if not role:
                return _auth_error("Потрібно увійти повторно.")
            if roles and role not in roles:
                return _auth_error("Немає доступу до цієї дії.", 403)
            g.current_role = role
            return func(*args, **kwargs)

        return wrapper

    return decorator


@app.post("/api/login")
def login():
    payload = request.get_json(force=True, silent=True) or {}
    role = payload.get("role")
    password = payload.get("password") or ""

    expected = None
    if role == "admin":
        expected = ADMIN_PASSWORD
    elif role == "screen":
        expected = SCREEN_PASSWORD

    if expected is None:
        return _auth_error("Невідома роль.", 400)

    if password != expected:
        return _auth_error("Невірний пароль.")

    token = _generate_token(role)
    return jsonify({"token": token, "role": role})


@app.get("/api/orders")
@require_role("admin", "screen")
def list_orders():
    with _lock:
        # Завжди завантажуємо свіжі дані з диску перед поверненням
        _load_orders_from_disk()
        return jsonify(_orders)


@app.post("/api/orders")
@require_role("admin")
def create_order():
    payload = request.get_json(force=True, silent=True) or {}
    items_text = (payload.get("itemsText") or "").strip()
    name = (payload.get("name") or "").strip()
    note = (payload.get("note") or "").strip()
    items_payload = payload.get("items")
    normalized_items, computed_total = _normalize_items(items_payload)
    total_price = computed_total if normalized_items else _sanitize_money(payload.get("totalPrice")) or 0.0
    client_paid = _sanitize_money(payload.get("clientPaid"))
    change_due = _sanitize_money(payload.get("changeDue"))

    if not items_text:
        return jsonify({"error": "Поле 'itemsText' є обов'язковим."}), 400

    with _lock:
        order = {
            "id": f"o_{uuid.uuid4().hex}",
            "number": _get_next_number(),
            "name": name,
            "itemsText": items_text,
            "status": "new",
            "createdAt": int(time.time() * 1000),
            "items": normalized_items,
            "totalPrice": total_price,
            "clientPaid": client_paid,
            "changeDue": change_due,
            "note": note,
        }
        _orders.append(order)
        _save_orders_to_disk()
        _broadcast_orders()
        return jsonify(order), 201


@app.patch("/api/orders/<order_id>")
@require_role("admin")
def update_order(order_id: str):
    payload = request.get_json(force=True, silent=True) or {}
    allowed_fields = {"name", "itemsText", "status"}

    if not any(field in payload for field in allowed_fields):
        return jsonify({"error": "Немає жодного поля для оновлення."}), 400

    with _lock:
        order = _find_order(order_id)
        if not order:
            return jsonify({"error": "Замовлення не знайдене."}), 404

        for key in allowed_fields:
            if key in payload:
                value = payload[key]
                if isinstance(value, str):
                    value = value.strip()
                if key == "status":
                    if value not in ALLOWED_STATUSES:
                        return jsonify({"error": "Неприпустимий статус."}), 400
                    if value != order.get("status"):
                        _apply_status_transition(order, value)
                    order[key] = value
                else:
                    order[key] = value

        _save_orders_to_disk()
        _broadcast_orders()
        return jsonify(order)


@app.delete("/api/orders/<order_id>")
@require_role("admin")
def delete_order(order_id: str):
    global _orders, _last_number
    with _lock:
        filtered = [order for order in _orders if order.get("id") != order_id]
        if len(filtered) == len(_orders):
            return jsonify({"error": "Замовлення не знайдене."}), 404
        _orders = filtered
        # якщо видаляємо останній номер – підтягуємо лічильник до найбільшого наявного
        _last_number = (
            max((order.get("number") or 0) for order in _orders) if _orders else 0
        )
        _save_orders_to_disk()
        _broadcast_orders()
        return "", 204


@app.delete("/api/orders")
@require_role("admin")
def clear_orders():
    global _orders, _last_number
    with _lock:
        _orders = []
        _last_number = 0
        _save_orders_to_disk()
        _broadcast_orders()
        return "", 204


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def serve_index():
    return send_from_directory(APP_ROOT, "Cafe22.html")


@app.route("/<path:path>")
def serve_static(path: str):
    target = APP_ROOT / path
    if target.is_file():
        return send_from_directory(APP_ROOT, path)
    abort(404)


@socketio.on("connect")
def handle_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get("token")
    role = _verify_token(token or "")
    if role not in {"admin", "screen"}:
        raise ConnectionRefusedError("unauthorized")
    # Завжди завантажуємо свіжі дані з диску перед відправкою
    with _lock:
        _load_orders_from_disk()
    socketio.emit("orders_updated", _orders, room=request.sid)


@socketio.on("ping")
def handle_ping():
    """Обробка ping для heartbeat механізму"""
    socketio.emit("pong")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, allow_unsafe_werkzeug=True)

