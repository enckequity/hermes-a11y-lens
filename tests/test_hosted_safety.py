"""Hosted-workspace defaults: loopback/private refusal, provisioned settings, no downloads, neutral text."""
import dataclasses
import http.server
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from a11y_lens import cli, runner, service, tools
from a11y_lens.policy import PolicyError, validate_target


# ---------------------------------------------------------------- policy
@pytest.mark.parametrize("url", ["http://localhost:8642/", "http://127.0.0.1:5432", "http://[::1]:8080/x",
                                 "http://127.9.9.9/", "http://localhost.localdomain:3000"])
def test_loopback_refused_by_default(url):
    with pytest.raises(PolicyError) as e:
        validate_target(url)
    assert e.value.code == "loopback_refused"


def test_allowed_origins_cannot_reopen_loopback():
    with pytest.raises(PolicyError) as e:
        validate_target("http://127.0.0.1:8642/", ["http://127.0.0.1:8642"])
    assert e.value.code == "loopback_refused"


@pytest.mark.parametrize("host", ["http://10.1.2.3", "http://172.20.0.4", "http://192.168.0.1", "http://169.254.169.254",
                                  "http://[fe80::1]", "http://[fd00:ec2::254]", "http://100.100.100.200", "http://0.0.0.0"])
def test_private_link_local_and_metadata_refused_even_with_loopback_opt_in(host):
    with pytest.raises(PolicyError) as e:
        validate_target(host + "/", [host], allow_loopback=True)
    assert e.value.code == "private_address"


def test_metadata_hostname_refused_after_dns(monkeypatch):
    import ipaddress
    from a11y_lens import policy
    monkeypatch.setattr(policy, "resolve_host", lambda h: [ipaddress.ip_address("169.254.169.254")])
    with pytest.raises(PolicyError) as e:
        validate_target("http://metadata.google.internal/", ["http://metadata.google.internal"])
    assert e.value.code == "private_address"


def test_local_file_server_is_pinned_to_its_exact_origin():
    t = validate_target("http://127.0.0.1:41234/index.html", local_server=True)
    assert t.loopback and t.strict_origins == ["http://127.0.0.1:41234"]


def test_policy_messages_are_white_label():
    for url, kw in (("https://example.com", {}), ("http://localhost:1", {})):
        with pytest.raises(PolicyError) as e:
            validate_target(url, **kw)
        assert "hermes" not in str(e.value).lower()


# ---------------------------------------------------------------- settings from config.yaml
class FakeCtx:
    def __init__(self, settings):
        self.settings = dict(settings)

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def set_config(self, key, value):
        self.settings[key] = value


def test_defaults_are_hosted_safe():
    s = tools.Runtime(FakeCtx({})).settings()
    assert s.allowed_origins == [] and s.allow_loopback is False and s.allow_browser_install is False


def test_provisioned_settings_are_read():
    s = tools.Runtime(FakeCtx({"allowed_origins": ["https://a.example", "https://b.example"],
                               "allow_loopback": True, "allow_browser_install": "true"})).settings()
    assert s.allowed_origins == ["https://a.example", "https://b.example"]
    assert s.allow_loopback is True and s.allow_browser_install is True


def test_allowed_origins_accepts_comma_string_and_bools_fail_closed():
    s = tools.Runtime(FakeCtx({"allowed_origins": "https://a.example, https://b.example",
                               "allow_loopback": "nope", "allow_browser_install": None})).settings()
    assert s.allowed_origins == ["https://a.example", "https://b.example"]
    assert s.allow_loopback is False and s.allow_browser_install is False


def test_cli_allow_writes_the_same_setting():
    import argparse
    ctx = FakeCtx({})
    rt = tools.Runtime(ctx)
    handle = cli.make_cli_handler(rt, ctx)
    assert handle(argparse.Namespace(a11y_cmd="allow", origin="HTTPS://Staging.Example.com:443/x")) == 0
    assert ctx.settings["allowed_origins"] == ["https://staging.example.com"]
    assert rt.settings().allowed_origins == ["https://staging.example.com"]


# ---------------------------------------------------------------- no downloads
def test_install_refuses_unless_enabled(monkeypatch):
    import argparse
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: calls.append(a) or 0)
    ctx = FakeCtx({})
    handle = cli.make_cli_handler(tools.Runtime(ctx), ctx)
    assert handle(argparse.Namespace(a11y_cmd="install")) == 2 and calls == []
    ctx.settings["allow_browser_install"] = True
    assert handle(argparse.Namespace(a11y_cmd="install")) == 0 and len(calls) == 1


def test_scan_path_never_invokes_playwright_install():
    root = Path(__file__).resolve().parents[1]
    for name in ("worker.py", "runner.py", "service.py", "tools.py", "policy.py"):
        text = (root / name).read_text(encoding="utf-8")
        assert '"install"' not in text and "playwright install" not in text, name
    assert "subprocess" not in (root / "worker.py").read_text(encoding="utf-8")


def test_image_chromium_fallback(tmp_path, monkeypatch):
    exe = tmp_path / "chrome"
    exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    rec = tmp_path / "chromium-executable-path"
    rec.write_text(str(exe) + "\n")
    monkeypatch.setattr(runner, "IMAGE_CHROMIUM_PATH_FILE", rec)
    assert runner.image_chromium_executable() == str(exe)
    rec.write_text(str(tmp_path / "missing"))
    assert runner.image_chromium_executable() is None


# ---------------------------------------------------------------- local file server
def test_local_server_serves_only_web_assets(tmp_path):
    site = tmp_path / "proj" / "site"; site.mkdir(parents=True)
    (site / "index.html").write_text("<html>ok</html>")
    (site / ".env").write_text("SECRET=1")
    (site / "auth.json").write_text("{}")
    (site / ".git").mkdir(); (site / ".git" / "config.html").write_text("x")
    (site / "a.css").write_text("body{}")
    with runner.serve_directory(site) as base:
        def status(path):
            try:
                return urllib.request.urlopen(base + path, timeout=5).status
            except urllib.error.HTTPError as exc:
                return exc.code
        assert status("/index.html") == 200 and status("/a.css") == 200
        assert status("/.env") == 404 and status("/auth.json") == 404 and status("/.git/config.html") == 404
        (site / "index.html").unlink()
        assert status("/") == 404  # no directory listing


# ---------------------------------------------------------------- real browser: other local ports are unreachable
class _Counter:
    def __init__(self, routes=None):
        hits = self.hits = []
        routes = routes or {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append(self.path)
                r = routes.get(self.path)
                if r:
                    return r(self)
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(b"<html><body><p id=secret>INTERNAL-SECRET</p></body></html>")

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


def test_local_file_page_cannot_reach_other_local_ports(store, settings, tmp_path):
    victim = _Counter()
    site = tmp_path / "proj" / "site"; site.mkdir(parents=True)
    v = f"http://127.0.0.1:{victim.port}"
    (site / "index.html").write_text(
        '<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>x</h1>'
        f'<img src="{v}/img" alt="a"><iframe title="f" src="{v}/frame"></iframe>'
        f'<iframe title="g" src="http://localhost:{victim.port}/frame2"></iframe>'
        f'<iframe title="m" src="http://169.254.169.254/latest/meta-data/"></iframe>'
        f'<script>fetch("{v}/fetch").catch(()=>{{}});</script></main></body></html>')
    try:
        res = service.scan(store, settings, str(site / "index.html"))
    finally:
        victim.close()
    assert victim.hits == []
    assert "INTERNAL-SECRET" not in str(res)
    assert res["status"] in ("complete", "incomplete")


def test_redirect_hop_to_other_local_port_is_stopped(store, settings):
    victim = _Counter()

    def redir(h):
        h.send_response(302); h.send_header("Location", f"http://127.0.0.1:{victim.port}/stolen"); h.end_headers()

    page = ('<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>x</h1>'
            '<iframe title="r" src="/redir"></iframe><img alt="i" src="/redir"></main></body></html>')

    def index(h):
        h.send_response(200); h.send_header("Content-Type", "text/html"); h.end_headers(); h.wfile.write(page.encode())

    target = _Counter({"/": index, "/redir": redir})
    try:
        # Opt-in loopback mode pins only the target's own host name ("localhost"); the redirect hop to
        # 127.0.0.1:<victim> is invisible to Playwright routing and must be stopped by the proxy.
        res = service.scan(store, dataclasses.replace(settings, allow_loopback=True), f"http://localhost:{target.port}/")
    finally:
        target.close(); victim.close()
    assert victim.hits == []
    assert "INTERNAL-SECRET" not in str(res)


def test_main_navigation_redirect_to_metadata_fails(store, settings, tmp_path):
    site = tmp_path / "proj" / "site"; site.mkdir(parents=True)
    (site / "index.html").write_text('<!doctype html><html lang="en"><head><title>t</title>'
                                     '<meta http-equiv="refresh" content="0;url=http://169.254.169.254/"></head>'
                                     '<body><main><h1>x</h1></main></body></html>')
    res = service.scan(store, settings, str(site / "index.html"))
    assert "169.254.169.254" not in str(res.get("scanned_url"))


# ---------------------------------------------------------------- launch flags
def test_chromium_args_pin_exact_origin_and_ignore_overrides():
    from a11y_lens import worker
    args = worker.chromium_args({"pinned_hosts": {"127.0.0.1": "127.0.0.1"}, "strict_origins": ["http://127.0.0.1:41234"],
                                 "chromium_args": ["--proxy-server=direct://", "--no-proxy-server",
                                                   "--host-resolver-rules=MAP * 10.0.0.1", "--no-sandbox"]})
    assert "--proxy-bypass-list=<-loopback>;127.0.0.1:41234" in args
    assert f"--proxy-server={worker.BLACKHOLE_PROXY}" in args
    assert "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" in args
    assert "--no-sandbox" in args and not any(a in args for a in ("--proxy-server=direct://", "--no-proxy-server"))
    remote = worker.chromium_args({"pinned_hosts": {"example.com": "93.184.216.34"}})
    assert "--proxy-bypass-list=<-loopback>;example.com" in remote
    assert "--host-resolver-rules=MAP example.com 93.184.216.34, MAP * ~NOTFOUND" in remote


def test_strict_origin_redirect_hop_to_same_host_other_port_is_stopped(settings):
    """Drives the worker directly in local-file-server mode (exact origin) against a server that redirects."""
    from a11y_lens import worker
    victim = _Counter()

    def redir(h):
        h.send_response(302); h.send_header("Location", f"http://127.0.0.1:{victim.port}/stolen"); h.end_headers()

    page = ('<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>x</h1>'
            '<iframe title="r" src="/redir"></iframe><img alt="i" src="/redir"></main></body></html>')

    def index(h):
        h.send_response(200); h.send_header("Content-Type", "text/html"); h.end_headers(); h.wfile.write(page.encode())

    target = _Counter({"/": index, "/redir": redir})
    origin = f"http://127.0.0.1:{target.port}"
    job = {"url": origin + "/", "pinned_hosts": {"127.0.0.1": "127.0.0.1"}, "strict_origins": [origin],
           "viewport": {"width": 800, "height": 600}, "timeout_s": 20, "tags": ["wcag2a"],
           "axe_path": str(runner.AXE_PATH), "browser_executable": settings.browser_executable or None,
           "fallback_executable": runner.image_chromium_executable(), "chromium_args": settings.chromium_args,
           "settle_ms": 0}
    try:
        res = worker.run(job)
    finally:
        target.close(); victim.close()
    assert victim.hits == []
    assert "INTERNAL-SECRET" not in str(res)



def test_folder_requests_never_serve_an_index_link(tmp_path):
    site = tmp_path / "site"
    (site / "x").mkdir(parents=True)
    (site / "index.html").write_text("<html><body>ok</body></html>")
    secret = tmp_path / "secret.html"
    secret.write_text("TOKEN=abc")
    (site / "x" / "index.html").symlink_to(secret)
    with runner.serve_directory(site) as base:
        assert b"ok" in urllib.request.urlopen(f"{base}/index.html").read()
        for path in ("/x/", "/x", "/", "/x/index.html"):
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(base + path).read()


def test_operator_chromium_args_cannot_loosen_confinement():
    from a11y_lens import worker

    args = worker.chromium_args({"pinned_hosts": {"example.com": "93.184.216.34"}, "chromium_args": [
        "-proxy-server=direct://", "--force-webrtc-ip-handling-policy=default", "-no-proxy-server", "--lang=en"]})
    assert "--lang=en" in args
    assert not any(a.startswith(("-proxy-server", "-no-proxy")) for a in args)
    assert args.count("--force-webrtc-ip-handling-policy=disable_non_proxied_udp") == 1
    assert "--force-webrtc-ip-handling-policy=default" not in args
