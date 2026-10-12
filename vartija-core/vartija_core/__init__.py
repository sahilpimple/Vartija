"""Vartija core: the reusable, challenge-agnostic layer.

Everything regulation-, sector- or challenge-specific lives in ``config/`` (YAML),
``corpus/`` (documents for retrieval) and ``config/prompts/`` (agent prompts), so the
team can re-skin the product for a new challenge without touching this code.
"""

__version__ = "0.1.0"
