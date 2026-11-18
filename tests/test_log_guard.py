from security.log_guard import (
    sanitize_log,
    escape_json,
    is_control_char,
    redact,
    format_record
)


def test_newline():
    assert '\\n' in sanitize_log('a\nb')

def test_crlf():
    assert '\\r' in sanitize_log('a\r\nb')

def test_ansi():
    assert '\x1b' not in sanitize_log('\x1b[31mred')

def test_unicode():
    assert '\u2028' not in sanitize_log('a\u2028b')

def test_json():
    assert escape_json('a"b') == 'a\\"b'

def test_length():
    assert len(sanitize_log('a' * 10000)) <= 1024

def test_identity():
    assert format_record({'user': 'u', 'msg': 'm'})['user'] == 'u'

def test_redact():
    assert redact({'password': 'x'})['password'] == '***'

def test_multi():
    assert '\n' not in sanitize_log('a' + chr(10) + 'b')

def test_empty():
    assert sanitize_log('') == ''

def test_control():
    assert is_control_char(chr(7)) is True

def test_path():
    assert '/etc/passwd' not in format_record({'error': '/etc/passwd'})['error']

def test_secret():
    assert redact({'token': 'x'})['token'] == '***'

def test_safe():
    assert sanitize_log('hello') == 'hello'

def test_record():
    assert format_record({'level': 'INFO', 'msg': 'm'})['level'] == 'INFO'
