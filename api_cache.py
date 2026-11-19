"""
IPeek caching and API-key support (backlog item: Caching and API-key support)
=============================================================================

The free tiers of the IP-details APIs have limits (ipapi.co allows about
1,000 requests a day), and batch lookups can use that up quickly. This
module helps in two ways:

Caching
-------
Successful IP-details answers are saved for CACHE_HOURS (24 by default), so
looking up the same address again, or seeing it again in another batch file,
does not send another request. Errors are never cached, so a failed lookup is
tried again next time. Only the newest MAX_ENTRIES addresses are kept.

The cache is one JSON file in the user's app-data folder, next to the history:
    Windows: %APPDATA%\\IPeek\\cache.json
    macOS:   ~/Library/Application Support/IPeek/cache.json
    Linux:   ~/.local/share/ipeek/cache.json

API keys
--------
A paid ipapi.co key raises its limit, and an ipstack key adds ipstack as an
extra provider. Keys are read from environment variables first, then from
config.json in the same app-data folder:

    IPEEK_IPAPI_KEY     or   {"ipapi_key": "..."}
    IPEEK_IPSTACK_KEY   or   {"ipstack_key": "..."}
                             {"cache_hours": 24}     (0 turns the cache off)

Keys are never written to the cache, the history, or any error message.

The cache is OFF until an app turns it on (ENABLED = True). ip_info_app.py and
gui_app.py do that only when they are started as programs, so the unit tests
never read or write a real cache file.
"""

import json
import os
import platform
import threading
import time

ENABLED = False          # set to True by the CLI/GUI when started as programs
READ = True              # False (--no-cache) = always ask the API, but still save the answer
PATH = None              # None = default cache path; tests set a temporary file
CONFIG_PATH = None       # None = default config path; tests set a temporary file
CACHE_HOURS = 24         # used when config.json doesn't set cache_hours
MAX_ENTRIES = 2000

KEY_ENV = {"ipapi_key": "IPEEK_IPAPI_KEY", "ipstack_key": "IPEEK_IPSTACK_KEY"}

_lock = threading.Lock()  # the GUI runs lookups in worker threads


def app_dir():
    """IPeek's folder in this user's app-data folder (same one as history.py)."""
    system = platform.system()
    if system == "Windows":
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "IPeek")
    if system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/IPeek")
    return os.path.join(os.environ.get("XDG_DATA_HOME")
                        or os.path.expanduser("~/.local/share"), "ipeek")


def cache_path():
    return PATH or os.path.join(app_dir(), "cache.json")


def config_path():
    return CONFIG_PATH or os.path.join(app_dir(), "config.json")


# ---------------------------------------------------------------------------
# Settings and API keys
# ---------------------------------------------------------------------------
def load_config():
    """The settings in config.json as a dict ({} if missing or unreadable)."""
    try:
        with open(config_path(), encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def api_key(name):
    """An API key ('ipapi_key' or 'ipstack_key'), or None if none is set.

    The environment variable wins over config.json.
    """
    value = os.environ.get(KEY_ENV[name]) or load_config().get(name)
    value = str(value).strip() if value else ""
    return value or None


def cache_hours():
    """How long answers are kept, in hours (0 = cache off)."""
    try:
        return max(0.0, float(load_config().get("cache_hours", CACHE_HOURS)))
    except (TypeError, ValueError):
        return float(CACHE_HOURS)


def redact(text):
    """Text with every configured API key replaced by '***'.

    requests puts the full URL, query string included, in its error
    messages, so this keeps keys out of anything shown on screen.
    """
    text = str(text)
    for name in KEY_ENV:
        key = api_key(name)
        if key:
            text = text.replace(key, "***")
    return text


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------
def _read():
    try:
        with open(cache_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}                         # a damaged cache is simply rebuilt


def _write(data):
    path = cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)                 # never leaves a half-written file


def get(ip, now=None):
    """The cached details for ip, or None if not cached, expired or cache off.

    The returned dict has "cached": True and "cached_at" (when it was fetched).
    """
    hours = cache_hours()
    if not ENABLED or not READ or hours <= 0:
        return None
    now = time.time() if now is None else now
    with _lock:
        entry = _read().get(ip)
    if not isinstance(entry, dict) or not isinstance(entry.get("details"), dict):
        return None
    saved = entry.get("time", 0)
    if not isinstance(saved, (int, float)) or now - saved > hours * 3600:
        return None
    details = dict(entry["details"])
    details["cached"] = True
    details["cached_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(saved))
    return details


def put(ip, details, now=None):
    """Save a successful details dict for ip. Errors are not cached."""
    if not ENABLED or cache_hours() <= 0 or not details or "error" in details:
        return
    now = time.time() if now is None else now
    clean = {k: v for k, v in details.items() if k not in ("cached", "cached_at")}
    with _lock:
        data = _read()
        data.pop(ip, None)                # re-insert so the newest is last
        data[ip] = {"time": now, "details": clean}
        if len(data) > MAX_ENTRIES:
            data = dict(list(data.items())[-MAX_ENTRIES:])
        try:
            _write(data)
        except OSError:
            pass                          # the cache must never stop a lookup


def clear():
    """Delete the cache file. Returns True if there was one."""
    with _lock:
        try:
            os.remove(cache_path())
            return True
        except FileNotFoundError:
            return False


def status():
    """A short summary for --cache-info and the GUI."""
    keys = [label for name, label in (("ipapi_key", "ipapi.co"), ("ipstack_key", "ipstack"))
            if api_key(name)]
    with _lock:
        count = len(_read())
    return {"cache_file": cache_path(), "config_file": config_path(),
            "cached_addresses": count, "cache_hours": cache_hours(),
            "api_keys": keys}
