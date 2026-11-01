"""Errors safe to show without leaking network or filesystem internals."""


class DetectionError(Exception):
    """An operational failure, never evidence of safety."""
