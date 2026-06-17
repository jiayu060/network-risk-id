"""Text analysis utilities: entropy, n-gram scoring."""

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def consonant_vowel_ratio(text: str) -> float:
    """Ratio of consonants to vowels in text."""
    vowels = set("aeiouAEIOU")
    v_count = sum(1 for c in text if c in vowels)
    c_count = sum(1 for c in text if c.isalpha() and c not in vowels)
    if v_count == 0:
        return float("inf") if c_count > 0 else 0.0
    return c_count / v_count


def max_consonant_run(text: str) -> int:
    """Maximum consecutive consonants."""
    vowels = set("aeiouAEIOU")
    max_run = 0
    current = 0
    for c in text:
        if c.isalpha() and c not in vowels:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


def ngram_frequency_score(text: str, n: int = 2) -> float:
    """Score how 'natural' text appears based on n-gram repetition.
    Lower score = more repetitive (DGA-like).
    """
    if len(text) < n:
        return 0.0
    ngrams = set()
    for i in range(len(text) - n + 1):
        ngrams.add(text[i:i + n])
    # Unique n-gram ratio
    possible = len(text) - n + 1
    return len(ngrams) / max(possible, 1)


def digit_fraction(text: str) -> float:
    """Fraction of characters that are digits."""
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / len(text)
