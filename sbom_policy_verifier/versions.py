"""Generic, offline semantic-ish version comparison and range checks."""

from __future__ import annotations

import re
from functools import total_ordering

_TOKEN_RE = re.compile(r"\d+|[a-z]+")


@total_ordering
class Version:
    """Comparable version built from dotted numeric / alphabetic tokens."""

    def __init__(self, text: str):
        self.raw = text
        self._tokens = _TOKEN_RE.findall(text.lower())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._tokens == other._tokens

    def __lt__(self, other: "Version") -> bool:
        return _compare_tokens(self._tokens, other._tokens) < 0

    def __hash__(self) -> int:
        return hash(tuple(self._tokens))

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


def _compare_tokens(left: list[str], right: list[str]) -> int:
    size = max(len(left), len(right))
    for index in range(size):
        if index >= len(left) or index >= len(right):
            # SemVer-style prefix rule: a shorter list is greater when the
            # remaining tokens are pre-release labels (alphabetic), but
            # smaller when they are numeric build tokens.
            remaining = (right if index >= len(left) else left)[index:]
            alpha_remaining = all(not token.isdigit() for token in remaining)
            if index >= len(left):
                return 1 if alpha_remaining else -1
            return -1 if alpha_remaining else 1
        left_token = left[index]
        right_token = right[index]
        if left_token == right_token:
            continue
        left_is_digit = left_token.isdigit()
        right_is_digit = right_token.isdigit()
        if left_is_digit and right_is_digit:
            result = int(left_token) - int(right_token)
        elif left_is_digit:
            result = 1
        elif right_is_digit:
            result = -1
        else:
            result = -1 if left_token < right_token else 1
        if result != 0:
            return -1 if result < 0 else 1
    return 0


_COMPARATORS = ("==", "!=", ">=", "<=", ">", "<", "=")


class InvalidConstraint(ValueError):
    """Raised when a version constraint cannot be parsed."""


def _check_single(version: Version, expression: str) -> bool:
    expression = expression.strip()
    if not expression:
        raise InvalidConstraint("empty version constraint")
    comparator = "=="
    for candidate in _COMPARATORS:
        if expression.startswith(candidate):
            comparator = candidate
            expression = expression[len(candidate) :].strip()
            break
    if not expression:
        raise InvalidConstraint("constraint is missing a version")
    target = Version(expression)
    if comparator in ("=", "=="):
        return version == target
    if comparator == "!=":
        return version != target
    if comparator == ">":
        return version > target
    if comparator == ">=":
        return version >= target
    if comparator == "<":
        return version < target
    return version <= target


def version_in_range(version_text: str | None, spec: str | list[str]) -> bool:
    """Return whether ``version_text`` satisfies the range specification.

    A spec may be a single constraint string or a list of them.  Constraints
    separated by commas inside one string must all hold (AND); entries of a
    list are alternative groups (OR).  A bare version means an exact match.
    """

    if version_text is None:
        return False
    groups = [spec] if isinstance(spec, str) else list(spec)
    if not groups:
        raise InvalidConstraint("empty version range")
    version = Version(version_text)
    for group in groups:
        if not isinstance(group, str) or not group.strip():
            raise InvalidConstraint(f"invalid constraint group: {group!r}")
        if all(_check_single(version, part) for part in group.split(",")):
            return True
    return False
