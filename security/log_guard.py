"""Hardening helpers for audit-log output.

Threat model: once raw user input is written to the audit log, an attacker can
try to forge whole records.  Every helper below closes one injection channel:

* ``sanitize_log`` turns untrusted text into a single-line, fixed-length,
  terminal-safe string (CR/LF escaping, ANSI stripping, Unicode line-separator
  normalization, control-character encoding, length cap).
* ``escape_json`` produces JSON string *content* (no surrounding quotes) with
  quotes, backslashes and control characters properly escaped.
* ``is_control_char`` identifies Unicode Cc control characters.
* ``redact`` masks sensitive fields by key name.
* ``format_record`` builds a record with a fixed field order, server-side
  identity override, multiline marking, path scrubbing and whitelist-only
  exception serialization.

The functions never raise on hostile input: non-string values are coerced,
unknown structures fall back to ``str()`` instead of ``repr()``.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Mapping, Sequence

__all__ = [
    'sanitize_log',
    'escape_json',
    'is_control_char',
    'redact',
    'format_record',
    'MAX_LOG_LENGTH',
    'REDACTION_MASK',
]

MAX_LOG_LENGTH = 1024
REDACTION_MASK = '***'
_TRUNCATION_MARKER = '...[truncated]'
_PATH_MASK = '[path]'

# CSI (ESC [ ... final), OSC (ESC ] ... BEL/ST) and simple two-byte escapes.
_ANSI_ESCAPE_RE = re.compile(
    r'\x1b(?:'
    r'\[[0-?]*[ -/]*[@-~]'              # CSI sequence
    r'|\][^\x07\x1b]*(?:\x07|\x1b\\)'   # OSC hyperlink/title sequence
    r'|[@-Z\\-_]'                        # ESC + single intermediate/final
    r')'
)

# Line breaks that are not ASCII LF/CR but still split logical lines.
_UNICODE_LINE_SEPARATORS = (' ', ' ', ' ')

_SENSITIVE_KEYS = frozenset({
    'password', 'passwd', 'pwd',
    'token', 'access_token', 'refresh_token', 'id_token',
    'secret', 'client_secret',
    'api_key', 'apikey',
    'authorization', 'auth',
    'credential', 'credentials',
    'session', 'session_id',
    'cookie', 'set_cookie',
    'private_key',
})
# Substring match catches e.g. "user_password", "x-api-key", "primaryToken".
_SENSITIVE_SUBSTRINGS = (
    'password', 'passwd', 'token', 'secret', 'credential', 'apikey',
    'api_key',
)

_ERROR_KEYS = frozenset({'error', 'exception', 'exc', 'traceback', 'stack'})
_IDENTITY_KEYS = frozenset({
    'user', 'username', 'actor', 'principal', 'subject',
})
# Fixed output order; unknown keys are appended alphabetically afterwards.
_CANONICAL_ORDER = (
    'timestamp', 'level', 'user', 'event', 'msg', 'multiline',
)

# Absolute POSIX paths and Windows drive paths.
_PATH_RE = re.compile(
    r'(?<![\w.-])'
    r'(?:'
    r'(?:/[A-Za-z0-9_.\-]+)+/?'
    r'|[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
    r')'
)

_JSON_ESCAPES = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}


def is_control_char(ch: str) -> bool:
    """Return True for a single Unicode Cc control character.

    Cc covers C0 (0x00-0x1F), DEL (0x7F) and C1 (0x80-0x9F).  Format
    characters (Cf, e.g. bidi overrides) are handled separately by the
    sanitizer but are not classified as control characters here.
    """
    return isinstance(ch, str) and len(ch) == 1 \
        and unicodedata.category(ch) == 'Cc'


def _is_dangerous_char(ch: str) -> bool:
    """Cc controls plus Cf format chars (bidi/zero-width spoofing)."""
    category = unicodedata.category(ch)
    return category in ('Cc', 'Cf')


def _encode_char(ch: str) -> str:
    code = ord(ch)
    if code <= 0xFF:
        return '\\x%02x' % code
    return '\\u%04x' % code


def sanitize_log(value: Any) -> str:
    """Make untrusted text safe to embed as one physical log line.

    1. ANSI escape sequences are stripped (terminal output cannot be
       rewritten); malformed/lone ESC bytes are removed too.
    2. Unicode line/paragraph separators are normalized to spaces.
    3. CR and LF are rendered as literal ``\\r`` / ``\\n`` -- the result can
       never span multiple physical lines.
    4. Remaining control/format characters (including bidi overrides) are
       encoded as visible ``\\xHH`` / ``\\uHHHH`` text.
    5. The result is capped at ``MAX_LOG_LENGTH``; a truncation marker is
       included inside that budget so oversized input cannot hide a forged
       suffix.
    """
    if not isinstance(value, str):
        value = str(value)
    if value == '':
        return ''

    text = _ANSI_ESCAPE_RE.sub('', value)
    text = text.replace('\x1b', '')

    for separator in _UNICODE_LINE_SEPARATORS:
        text = text.replace(separator, ' ')

    text = text.replace('\r', '\\r')
    text = text.replace('\n', '\\n')

    if _has_dangerous_char(text):
        text = ''.join(
            _encode_char(ch) if _is_dangerous_char(ch) else ch
            for ch in text
        )

    if len(text) > MAX_LOG_LENGTH:
        keep = MAX_LOG_LENGTH - len(_TRUNCATION_MARKER)
        text = text[:keep] + _TRUNCATION_MARKER
    return text


def _has_dangerous_char(text: str) -> bool:
    return any(_is_dangerous_char(ch) for ch in text)


def escape_json(value: Any) -> str:
    """Escape a string for use inside a JSON string (without quotes).

    Backslashes are doubled before quote escaping, and every control
    character becomes a ``\\u00XX`` escape, so attacker-controlled text can
    never break out of the enclosing JSON string.
    """
    if not isinstance(value, str):
        value = str(value)
    out = []
    for ch in value:
        if ch in _JSON_ESCAPES:
            out.append(_JSON_ESCAPES[ch])
        elif ord(ch) < 0x20 or unicodedata.category(ch) == 'Cc':
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def _normalize_key(key: Any) -> str:
    return re.sub(r'[^a-z0-9]+', '_', str(key).lower()).strip('_')


def _is_sensitive_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    if normalized in _SENSITIVE_KEYS:
        return True
    return any(part in normalized for part in _SENSITIVE_SUBSTRINGS)


def redact(record: Mapping[str, Any],
           extra_keys: Sequence[str] = ()) -> dict:
    """Return a copy of *record* with sensitive values masked.

    Matching is case-insensitive and ignores ``-``/``_``/space differences,
    with substring coverage for credential-bearing names.  The original
    mapping is never mutated.
    """
    if not isinstance(record, Mapping):
        raise TypeError('redact expects a mapping')
    extra = {str(key).lower() for key in extra_keys}
    result = dict(record)
    for key in list(result):
        if str(key).lower() in extra or _is_sensitive_key(key):
            result[key] = REDACTION_MASK
    return result


def _scrub_paths(text: str) -> str:
    """Replace absolute filesystem paths so internals cannot leak."""
    return _PATH_RE.sub(_PATH_MASK, text)


def _serialize_exception(exc: BaseException) -> str:
    """Whitelist-only exception serialization.

    Only the bare class name and ``args`` are emitted -- never ``__dict__``,
    ``repr()`` or a traceback (which carry file paths, locals and frames).
    Path-like strings inside the whitelisted args are scrubbed afterwards.
    """
    name = type(exc).__name__
    safe_args = [_scrub_paths(str(arg)) for arg in getattr(exc, 'args', ())]
    message = ' '.join(part for part in safe_args if part)
    if message:
        return '%s: %s' % (name, message)
    return name


def _contains_line_break(value: Any) -> bool:
    """True if any string inside *value* holds a (Unicode) line separator."""
    if isinstance(value, str):
        return any(sep in value for sep in (
            '\n', '\r', ' ', ' ', ' ',
        ))
    if isinstance(value, BaseException):
        return any(_contains_line_break(arg) for arg in value.args)
    if isinstance(value, Mapping):
        return any(
            _contains_line_break(k) or _contains_line_break(v)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_line_break(item) for item in value)
    return False


def _process_value(key: str, value: Any) -> Any:
    if isinstance(value, BaseException):
        # Whitelist serialization, then the normal single-line sanitizer.
        return sanitize_log(_serialize_exception(value))
    if isinstance(value, str):
        if key in _ERROR_KEYS:
            value = _scrub_paths(value)
        return sanitize_log(value)
    if isinstance(value, Mapping):
        return {
            sanitize_log(str(item_key)): _process_value(
                _normalize_key(item_key), item_value,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_process_value(key, item) for item in value]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    # Unknown type: never use repr(); coerce through the safe sanitizer.
    return sanitize_log(str(value))


def format_record(record: Mapping[str, Any],
                  identity: str | None = None) -> dict:
    """Build a hardened, ordered audit-log record.

    * Sensitive fields are redacted first.
    * *identity* (the authenticated principal, supplied by the server) always
      overrides client-controlled ``user``/``username``/``actor`` aliases.
    * Fields are emitted in a fixed canonical order; extras are sorted.
    * A ``multiline`` marker is added when raw input contained line breaks.
    * Exceptions are whitelist-serialized and paths are scrubbed from error
      fields; every string passes through :func:`sanitize_log`.
    """
    if not isinstance(record, Mapping):
        raise TypeError('format_record expects a mapping')

    source = redact(record)

    if identity is not None:
        # Server-side identity is authoritative: overwrite every alias the
        # client might have used to impersonate someone else.
        for alias in _IDENTITY_KEYS:
            source.pop(alias, None)
        source['user'] = str(identity)

    multiline = any(_contains_line_break(value) for value in record.values())
    if multiline:
        source['multiline'] = True

    canonical = [key for key in _CANONICAL_ORDER if key in source]
    extras = sorted(
        (key for key in source if key not in _CANONICAL_ORDER),
        key=str,
    )

    ordered: dict[str, Any] = {}
    for key in canonical + extras:
        safe_key = sanitize_log(str(key))
        ordered[safe_key] = _process_value(_normalize_key(key), source[key])
    return ordered
