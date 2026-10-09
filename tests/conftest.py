import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from support import McpSession, start  # noqa: E402


@pytest.fixture
def make_server(tmp_path):
    started = []

    def _make(**kw):
        srv = start(tmp_path, **kw)
        started.append(srv)
        return srv

    yield _make
    for s in started:
        s.stop()


@pytest.fixture
def server(make_server):
    return make_server()


@pytest.fixture
def session_for():
    def _session(srv, who, **kw):
        s = McpSession(srv.url, srv.token(who, **kw))
        r = s.initialize()
        assert r.status_code == 200, r.text
        return s
    return _session
