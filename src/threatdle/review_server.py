"""Tiny local HTTP server for puzzle review.

Serves the static review viewer and a small JSON API that reads
directly from puzzle_day in the SQLite database.

Usage:
    python -m threatdle serve-review --port 8000
"""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from threatdle.db.connection import get_connection
from threatdle.services.review_export import (
    get_review_day,
    list_review_days,
    list_review_snapshots,
)
from threatdle.services.game_api import (
    get_game_day,
    get_game_today,
    get_game_pool,
    validate_game_guess,
    get_game_summary,
)

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

GAME_TIMEZONE_ENV = "THREATDLE_GAME_TIMEZONE"


class ReviewHandler(BaseHTTPRequestHandler):
    """Request handler for the review server.

    Class-level attributes are set before the server starts:
    - db_path: path to the SQLite database
    - review_dir: path to the static review assets directory
    - public_dir: path to the static public game assets directory
    """

    db_path: Path
    review_dir: Path
    public_dir: Path

    def log_message(self, format, *args):
        # Suppress default stderr logging for cleaner output
        pass

    def _json_response(self, data: object, status: int = 200) -> None:
        body = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400) -> None:
        self._json_response({"error": message}, status)

    def _serve_static(self, path: str, base_dir: Path, default_file: str = "/index.html") -> None:
        if path in ("", "/"):
            path = default_file
        file_path = (base_dir / path.lstrip("/")).resolve()
        if not file_path.is_relative_to(base_dir.resolve()):
            self.send_error(403)
            return
        if not file_path.is_file():
            self.send_error(404)
            return
        content = file_path.read_bytes()
        content_type = CONTENT_TYPES.get(file_path.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path == "/api/snapshots":
            conn = get_connection(self.db_path)
            try:
                self._json_response(list_review_snapshots(conn))
            finally:
                conn.close()
            return

        if path == "/api/days":
            snapshot_id = params.get("snapshot_id")
            if not snapshot_id:
                self._error("snapshot_id query parameter required")
                return
            conn = get_connection(self.db_path)
            try:
                self._json_response(list_review_days(conn, snapshot_id))
            finally:
                conn.close()
            return

        if path == "/api/day":
            snapshot_id = params.get("snapshot_id")
            day_key = params.get("day_key")
            if not snapshot_id or not day_key:
                self._error("snapshot_id and day_key query parameters required")
                return
            conn = get_connection(self.db_path)
            try:
                data = get_review_day(conn, snapshot_id, day_key)
                if data is None:
                    self._error(f"No puzzle data for {day_key}", 404)
                else:
                    self._json_response(data)
            finally:
                conn.close()
            return
            
        if path == "/api/game/day":
            snapshot_id = params.get("snapshot_id")
            day_key = params.get("day_key")
            if not snapshot_id or not day_key:
                self._error("snapshot_id and day_key query parameters required")
                return
            conn = get_connection(self.db_path)
            try:
                data = get_game_day(conn, snapshot_id, day_key)
                if data is None:
                    self._error(f"No puzzle data for {day_key}", 404)
                else:
                    self._json_response(data)
            finally:
                conn.close()
            return

        if path == "/api/game/today":
            snapshot_id = params.get("snapshot_id")
            day_key = params.get("day_key")
            timezone_name = os.environ.get(GAME_TIMEZONE_ENV, "America/New_York")
            conn = get_connection(self.db_path)
            try:
                data = get_game_today(
                    conn,
                    snapshot_id=snapshot_id,
                    day_key=day_key,
                    timezone_name=timezone_name,
                )
                self._json_response(data)
            except ValueError as e:
                self._error(str(e), 400)
            finally:
                conn.close()
            return

        if path == "/api/game/pool":
            snapshot_id = params.get("snapshot_id")
            day_key = params.get("day_key")
            mode = params.get("mode")
            if not snapshot_id or not day_key or not mode:
                self._error("snapshot_id, day_key, and mode query parameters required")
                return
            conn = get_connection(self.db_path)
            try:
                data = get_game_pool(conn, snapshot_id, day_key, mode)
                self._json_response(data)
            except ValueError as e:
                self._error(str(e), 400)
            finally:
                conn.close()
            return

        if path == "/api/game/summary":
            snapshot_id = params.get("snapshot_id")
            day_key = params.get("day_key")
            if not snapshot_id or not day_key:
                self._error("snapshot_id and day_key query parameters required")
                return
            conn = get_connection(self.db_path)
            try:
                data = get_game_summary(conn, snapshot_id, day_key)
                self._json_response(data)
            except ValueError as e:
                self._error(str(e), 400)
            finally:
                conn.close()
            return

        # Player game SPA
        if path == "/game" or path.startswith("/game/"):
            # Strip the /game prefix to serve from public root
            serve_path = path[5:] if path.startswith("/game/") else "/"
            self._serve_static(serve_path, self.public_dir, default_file="/game.html")
            return

        # Fall through to specific file serving from public when the file exists there
        public_candidate = (self.public_dir / path.lstrip("/")).resolve()
        if public_candidate.is_relative_to(self.public_dir.resolve()) and public_candidate.is_file():
            self._serve_static(path, self.public_dir)
            return

        # Fall through to static review file serving
        self._serve_static(path, self.review_dir)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/game/guess":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._error("Request body required")
                return

            try:
                post_data = self.rfile.read(content_length)
                body = json.loads(post_data.decode("utf-8"))
            except json.JSONDecodeError:
                self._error("Invalid JSON body")
                return

            snapshot_id = body.get("snapshot_id")
            day_key = body.get("day_key")
            mode = body.get("mode")
            guess_key = body.get("guess_key")
            guess_steps = body.get("guess_steps")

            if not snapshot_id or not day_key or not mode:
                self._error("snapshot_id, day_key, and mode are required")
                return
            if mode == "timeline":
                if not isinstance(guess_steps, list) or not guess_steps:
                    self._error("guess_steps is required for timeline guesses")
                    return
            elif not guess_key:
                self._error("guess_key is required for non-timeline guesses")
                return

            conn = get_connection(self.db_path)
            try:
                result = validate_game_guess(
                    conn,
                    snapshot_id,
                    day_key,
                    mode,
                    guess_key,
                    guess_steps=guess_steps,
                )
                self._json_response(result)
            except ValueError as e:
                self._error(str(e), 400)
            finally:
                conn.close()
            return

        self.send_error(404)


def serve_review(db_path: Path, review_dir: Path, public_dir: Path, port: int = 8000) -> None:
    """Start the review server."""
    ReviewHandler.db_path = db_path
    ReviewHandler.review_dir = review_dir.resolve()
    ReviewHandler.public_dir = public_dir.resolve()

    server = HTTPServer(("127.0.0.1", port), ReviewHandler)
    print(f"Threatdle Server")
    print(f"  Game URL:   http://127.0.0.1:{port}/game")
    print(f"  Review URL: http://127.0.0.1:{port}/")
    print(f"  Database:   {db_path}")
    print(f"  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.shutdown()
