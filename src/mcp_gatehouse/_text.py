"""Characters a person can't see.

One definition with two uses. What an approver is shown has them escaped,
so a record can't redraw the prompt. What the server tells the model (a
tool's description, its schema) is refused if it has them, so nothing
reaches the model that a person reviewing the tool couldn't read.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

# What str.isprintable() calls printable and a screen still draws as
# nothing: Unicode's Default_Ignorable_Code_Point, less the categories
# isprintable() already rules out. Variation selectors are most of it, and
# U+E0100-E01EF is a known way to carry a byte per character.
_IGNORABLE = frozenset(
    [
        0x034F,  # COMBINING GRAPHEME JOINER
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
        0x17B4,  # KHMER VOWEL INHERENT AQ
        0x17B5,  # KHMER VOWEL INHERENT AA
        0x180B,  # MONGOLIAN FREE VARIATION SELECTOR ONE
        0x180C,
        0x180D,
        0x180F,  # MONGOLIAN FREE VARIATION SELECTOR FOUR
        0x3164,  # HANGUL FILLER
        0xFFA0,  # HALFWIDTH HANGUL FILLER
        *range(0xFE00, 0xFE10),  # VARIATION SELECTOR-1..16
        *range(0xE0100, 0xE01F0),  # VARIATION SELECTOR-17..256
    ]
)

# Line breaks and indentation: what a multi-line description is made of.
_LAYOUT = frozenset("\n\t")

# unicodedata has no name for these; the common ones get the name people
# know them by, the rest what kind of code point they are.
_CONTROLS = {
    0x00: "NULL",
    0x08: "BACKSPACE",
    0x0B: "LINE TABULATION",
    0x0C: "FORM FEED",
    0x0D: "CARRIAGE RETURN",
    0x1B: "ESCAPE",
    0x7F: "DELETE",
    0x85: "NEXT LINE",
}
_UNNAMED = {
    "Cc": "<control>",
    "Co": "<private use>",
    "Cs": "<surrogate>",
    "Cn": f"<unassigned in Unicode {unicodedata.unidata_version}>",
}


def invisible(ch: str) -> bool:
    """Whether a person shown ``ch`` sees nothing, or not what is there.

    Control and format characters (zero-width ones, bidi overrides, the
    tag block), line and paragraph separators, every space but the plain
    one, private-use and unassigned code points, and the characters Unicode
    says are drawn as nothing by default, variation selectors among them.
    Newline and tab count too: callers that allow them say so.
    """
    return not ch.isprintable() or ord(ch) in _IGNORABLE


def escaped(text: str) -> str:
    """``text`` with every invisible character written as its escape."""
    return "".join(ch.encode("unicode_escape").decode("ascii") if invisible(ch) else ch for ch in text)


def unseen(text: str) -> list[str]:
    """The invisible characters in ``text``, each once, in the order they
    first appear. Newline and tab are left out."""
    return list(dict.fromkeys(ch for ch in text if invisible(ch) and ch not in _LAYOUT))


def named(ch: str) -> str:
    """``ch`` as ``U+200B ZERO WIDTH SPACE``: the code point and its name,
    never the character."""
    name = unicodedata.name(ch, "") or _CONTROLS.get(ord(ch)) or _UNNAMED.get(unicodedata.category(ch), "")
    return f"U+{ord(ch):04X} {name}".rstrip()


def strings(value: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[tuple[str | int, ...], str, bool]]:
    """Every string inside ``value``, with the path to it: the values, and
    the keys of each mapping (``True`` in the third place, with the key as
    the last step of the path)."""
    if isinstance(value, str):
        yield path, value, False
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield (*path, key), key, True
            yield from strings(item, (*path, key))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            yield from strings(item, (*path, index))
    elif callable(getattr(value, "model_dump", None)):  # an Icon, or another pydantic model
        yield from strings(value.model_dump(mode="json", exclude_none=True), path)
