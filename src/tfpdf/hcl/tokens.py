"""Les sortes de jetons du lexeur HCL2."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .pos import Range


class TokenType(Enum):
    # Literals and names
    IDENT = auto()
    NUMBER = auto()

    # Quoted templates are lexed as a bracketed sequence rather than as one
    # token, because an interpolation contains arbitrary expressions that the
    # same lexer has to produce tokens for.
    OQUOTE = auto()  # opening "
    CQUOTE = auto()  # closing "
    QUOTED_LIT = auto()  # a run of literal characters inside a template
    TEMPLATE_INTERP = auto()  # ${
    TEMPLATE_CONTROL = auto()  # %{
    TEMPLATE_SEQ_END = auto()  # } closing an interpolation

    OHEREDOC = auto()  # <<EOF or <<-EOF
    CHEREDOC = auto()  # the terminating marker line

    # Brackets
    OBRACE = auto()
    CBRACE = auto()
    OBRACK = auto()
    CBRACK = auto()
    OPAREN = auto()
    CPAREN = auto()

    # Punctuation
    COMMA = auto()
    DOT = auto()
    COLON = auto()
    #: `::`, the separator in a provider-defined function name
    #: (`provider::aws::arn_parse(...)`, Terraform 1.8+).
    DOUBLE_COLON = auto()
    QUESTION = auto()
    EQUAL = auto()  # =
    FAT_ARROW = auto()  # =>
    ELLIPSIS = auto()  # ...

    # Operators
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    PERCENT = auto()
    BANG = auto()
    EQUAL_OP = auto()  # ==
    NOT_EQUAL = auto()  # !=
    LESS_THAN = auto()
    LESS_THAN_EQ = auto()
    GREATER_THAN = auto()
    GREATER_THAN_EQ = auto()
    AND = auto()  # &&
    OR = auto()  # ||

    NEWLINE = auto()
    COMMENT = auto()
    EOF = auto()
    INVALID = auto()


@dataclass(frozen=True, slots=True)
class Token:
    type: TokenType
    #: The exact source text, decoded. For QUOTED_LIT this is the text *after*
    #: escape processing, so the parser never re-processes escapes.
    text: str
    range: Range
    #: For QUOTED_LIT, the raw pre-escape text; used nowhere in judging, kept
    #: so an error message can quote what was written.
    raw: str = ""

    def __str__(self) -> str:
        return f"{self.type.name}({self.text!r}) at {self.range}"


#: Tokens that never carry meaning to the parser and are dropped before it
#: sees them. Newlines are *not* in here: HCL bodies are newline-terminated,
#: so the parser needs them.
IGNORED = frozenset({TokenType.COMMENT})
