"""Test harness. Synthetic election data and a throwaway data directory are used, never the production archive
(addendum 003 REQ-WIT-005: no synthetic/production confusion)."""
import os
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Must be set before observatory.config is imported.
_TMP = tempfile.mkdtemp(prefix="eio-test-")
os.environ["ELECTION_DATA_DIR"] = _TMP
os.environ["OBSERVATORY_TSA_URLS"] = ""

import time as _time  # noqa: E402

_REAL_SLEEP = _time.sleep

import pytest  # noqa: E402

from observatory import config, db  # noqa: E402
from observatory.parsers import NM_CSV_COLUMNS  # noqa: E402

TEST_SOURCE_ID = "test-csv"


def make_csv(rows):
    """rows: list of (race_id, race_name, area, party, cand_id, name, votes, precincts_label)"""
    out = [",".join(NM_CSV_COLUMNS)]
    for race_id, rname, area, party, cid, name, votes, prec in rows:
        out.append(f'{race_id},"{rname}","{party}","{area}",{cid},"{name}",1,{votes},0,{prec},,,,')
    return ("\n".join(out) + "\n").encode()


BASE_ROWS = [
    (1, "United States Senator", "", "DEM", 11, "ALICE ADAMS", 0, "0/100"),
    (1, "United States Senator", "", "REP", 12, "BOB BROWN", 0, "0/100"),
    (2, "Governor", "", "DEM", 21, "CARA CRUZ", 0, "0/100"),
    (2, "Governor", "", "REP", 22, "DAN DIAZ", 0, "0/100"),
]


class _Handler(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        s = self.state
        if path == "/csv":
            body = s["csv"]
            self.send_response(200)
            self.send_header("Content-Type", "application/text")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/503":
            self.send_response(503)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"busy")
        elif path == "/empty":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/partial":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            self.wfile.write(s["csv"][:200])
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_RDWR)
        elif path == "/gzip":
            import gzip
            body = gzip.compress(s["csv"])
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/slow":
            _REAL_SLEEP(4)   # tests patch time.sleep globally; the server must keep the real one
            self.send_response(200)
            self.end_headers()
        elif path == "/cookie":
            body = s["csv"]
            self.send_response(200)
            self.send_header("Set-Cookie", "SESSION=supersecret123; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture(scope="session")
def server():
    _Handler.state = {"csv": make_csv(BASE_ROWS)}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, _Handler.state
    srv.shutdown()


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    # every test gets its own database AND its own write-once directories
    from observatory import coverage
    for name in ("ARCHIVE_DIR", "MANIFEST_DIR", "AUDIT_DIR", "TIMESTAMP_DIR", "RESTRICTED_DIR", "CERT_DIR", "EXPORT_DIR"):
        d = tmp_path / name.lower()
        d.mkdir()
        monkeypatch.setattr(config, name, d)
    cov = tmp_path / "coverage"
    cov.mkdir()
    monkeypatch.setattr(coverage, "COVERAGE_DIR", cov)
    c = db.connect(tmp_path / "t.db")
    db.init_db(c)
    yield c
    c.close()


@pytest.fixture()
def src_factory(server):
    """Register a synthetic source (separate source_id, never a production id) pointing at the local server."""
    srv, _ = server

    def make(path="/csv", sid=TEST_SOURCE_ID, interval=60):
        s = dict(config.SOURCES[0])
        s.update(source_id=sid, source_name="TEST synthetic source", endpoint_url=f"http://127.0.0.1:{srv.server_port}{path}",
                 polling_interval_s=interval, parser_name="nm_sos_csv", parser_version="1", expected_format="csv",
                 source_classification=["RESEARCH_SOURCE"], authority_record_key="test")
        config.SOURCES_BY_ID[sid] = s
        return s
    yield make
    config.SOURCES_BY_ID.pop(TEST_SOURCE_ID, None)
