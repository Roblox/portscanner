"""Freshness-gated, idempotent TargetEvent dispatch."""

from .config import GeneratorConfig
from .handler import lambda_handler

__all__ = ["GeneratorConfig", "lambda_handler"]
