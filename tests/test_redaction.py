"""Which argument names are masked, and which values are opaque.

Whole-name matching alone let the names secrets actually go by
(github_token, db_password, openai_api_key) into the log in clear. A key
now also masks names that end in its words."""

from __future__ import annotations

import pytest

from mcp_gatehouse import DEFAULT_REDACT, Policy, redact_arguments
from mcp_gatehouse.policy import REDACTED, _normalize_key


def masked(name: str, keys: frozenset[str] = DEFAULT_REDACT) -> bool:
    return redact_arguments({name: "VALUE"}, keys)[name] == REDACTED


SECRET_NAMES = [
    "db_password", "github_token", "openai_api_key", "OPENAI_API_KEY", "openAIApiKey",
    "stripe_secret_key", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY",
    "bearer_token", "auth_token", "authToken", "session_token", "csrf_token",
    "secret_key", "apiToken", "x-api-key", "X-API-Key", "credentials", "gcp_credentials",
    "client_secret", "webhook_secret", "one_time_password", "proxy_authorization",
    "session_cookie", "user.password",
]

VISIBLE_NAMES = [
    "token_count", "max_tokens", "tokens", "tokenizer", "password_hint", "password_policy",
    "secret_santa", "cookie_consent", "api_key_id", "apiKeyId", "monkey", "keyword",
    "order_id", "note", "credit", "author", "passport", "ssn_last4",
]


@pytest.mark.parametrize("name", SECRET_NAMES)
def test_names_secrets_go_by_are_masked(name):
    assert masked(name)


@pytest.mark.parametrize("name", VISIBLE_NAMES)
def test_names_that_only_contain_a_secret_word_stay_visible(name):
    assert not masked(name)


def _old_rule(name: str, keys: frozenset[str]) -> bool:
    """0.3-0.5: whole names only, ignoring case, `_` and `-`."""
    return _normalize_key(name) in {_normalize_key(k) for k in keys}


def test_only_ever_masks_more():
    """Every name the old rule masked is still masked: every default key,
    in every spelling, and every name in this file."""
    spellings = set()
    for key in DEFAULT_REDACT:
        words = key.split("_")
        spellings |= {
            key, key.upper(), key.replace("_", "-"), key.replace("_", ""),
            words[0] + "".join(w.title() for w in words[1:]),  # camelCase
            "".join(w.title() for w in words),  # PascalCase
        }
    for name in spellings | set(SECRET_NAMES) | set(VISIBLE_NAMES):
        if _old_rule(name, DEFAULT_REDACT):
            assert masked(name), name
    assert all(masked(s) for s in spellings)


def test_custom_keys_match_by_words_not_letters():
    keys = frozenset({"pin"})
    assert masked("pin", keys) and masked("card_pin", keys) and masked("cardPin", keys)
    assert not masked("spin", keys) and not masked("opinion", keys) and not masked("pin_length", keys)


def test_multi_word_keys_match_as_a_tail():
    keys = frozenset({"card_number"})
    assert masked("card_number", keys) and masked("cardnumber", keys)
    assert masked("primary_card_number", keys) and masked("backupCardNumber", keys)
    assert not masked("number", keys) and not masked("card", keys)


def test_nested_compound_names_are_masked():
    safe = redact_arguments(
        {"config": {"github_token": "ghp_x", "repos": [{"deployKey": "k", "webhookSecret": "s"}]}},
        DEFAULT_REDACT,
    )
    assert safe["config"]["github_token"] == REDACTED
    assert safe["config"]["repos"][0]["webhookSecret"] == REDACTED
    assert safe["config"]["repos"][0]["deployKey"] == "k"  # *_key alone is not a secret


@pytest.mark.parametrize("value", [b"sk-live", bytearray(b"sk-live"), memoryview(b"sk-live")])
def test_bytes_likes_are_opaque(value):
    """bytearray and memoryview are sequences, and were logged byte by byte."""
    (safe,) = redact_arguments({"blob": value}, DEFAULT_REDACT).values()
    assert safe == f"«opaque:{type(value).__name__}»"


@pytest.mark.parametrize("name", ["contraseña", "пароль", "密码", "", "_", "--", "123", "a" * 500])
def test_unusual_names_do_not_break_matching(name):
    assert redact_arguments({name: "v"}, DEFAULT_REDACT)[name] == "v"


def test_any_collection_of_keys_works():
    for keys in (["pin"], ("pin",), {"pin"}, frozenset({"pin"}), Policy(redact={"pin"}).redact):
        assert redact_arguments({"card_pin": "1"}, keys) == {"card_pin": REDACTED}
