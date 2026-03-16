"""Text normalization utilities."""

from __future__ import annotations

import re
import unicodedata


SPACE_PATTERN = re.compile(r"\s+")
STRIP_PATTERN = re.compile(r"[\s._\-/]+")
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\([^)]+\)")
CITATION_PATTERN = re.compile(r"\(Citation:[^)]+\)")
HTML_TAG_PATTERN = re.compile(r"</?[^>]+>")
SPACE_BEFORE_PUNCTUATION_PATTERN = re.compile(r"\s+([,.;:!?])")
SINCE_YEAR_PATTERN = re.compile(r"\bsince(?: at least)? (?:[A-Za-z]+ )?(\d{4})\b", re.IGNORECASE)


def normalize_actor_name(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized = SPACE_PATTERN.sub(" ", normalized)
    normalized = STRIP_PATTERN.sub("", normalized)
    return normalized or None


def split_pipe_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split("|") if item.strip()]


def clean_attack_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = unicodedata.normalize("NFKC", value)
    cleaned = MARKDOWN_LINK_PATTERN.sub(r"\1", cleaned)
    cleaned = CITATION_PATTERN.sub("", cleaned)
    cleaned = HTML_TAG_PATTERN.sub("", cleaned)
    cleaned = SPACE_PATTERN.sub(" ", cleaned).strip()
    cleaned = SPACE_BEFORE_PUNCTUATION_PATTERN.sub(r"\1", cleaned)
    return cleaned or None


def extract_first_observed_year(value: str | None) -> int | None:
    cleaned = clean_attack_text(value)
    if not cleaned:
        return None
    match = SINCE_YEAR_PATTERN.search(cleaned)
    if match is None:
        return None
    return int(match.group(1))


def contains_name_reference(text: str | None, name: str | None) -> bool:
    if not text or not name:
        return False
    tokens = re.findall(r"[A-Za-z0-9]+", name)
    if not tokens:
        return False
    joined = r"[\W_]*".join(re.escape(token) for token in tokens)
    pattern = re.compile(rf"(?<![A-Za-z0-9]){joined}(?![A-Za-z0-9])", re.IGNORECASE)
    return pattern.search(text) is not None


def contains_any_name_reference(text: str | None, names: list[str]) -> bool:
    return any(contains_name_reference(text, name) for name in names)


def redact_names_from_text(text: str | None, names: list[str], replacement: str = "[THIS MALWARE]") -> str | None:
    """Redact occurrences of specific names (and aliases) from a block of text."""
    if not text or not names:
        return text
    
    redacted_text = text
    for name in names:
        if not name:
            continue
        tokens = re.findall(r"[A-Za-z0-9]+", name)
        if not tokens:
            continue
        joined = r"[\W_]*".join(re.escape(token) for token in tokens)
        pattern = re.compile(rf"(?<![A-Za-z0-9]){joined}(?![A-Za-z0-9])", re.IGNORECASE)
        redacted_text = pattern.sub(replacement, redacted_text)
        
    return redacted_text


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]
