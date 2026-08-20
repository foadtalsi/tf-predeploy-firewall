"""Le lexeur HCL2 : scanne de la source UTF-8 en un flux plat de jetons, chacun
portant son décalage en octets, sa ligne et sa colonne.

Trois aspects de HCL demandent plus qu'un scanneur de mots-clés :

- **Templates entre guillemets.** `"prefix-${var.env}"` se décompose en
  guillemet, littéral, interpolation et guillemet — pas un jeton opaque, sans
  quoi `${...}` serait inévaluable et la résolution de portée impossible.
- **Heredocs.** `<<-EOF` retire une indentation commune dont la quantité est
  fixée par le terminateur, donc résolue seulement une fois celui-ci trouvé.
- **Sauts de ligne significatifs.** Ce sont des jetons, sauf entre crochets où
  une expression peut se poursuivre — d'où le suivi de profondeur de crochets.

L'état est une **pile de modes**, parce que les templates s'imbriquent :
`"${join(",", ["${a}"])}"` est légal. L'analyseur consomme donc une liste plate,
sans retour vers le lexeur.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .diagnostics import Diagnostic as Diag
from .diagnostics import Diagnostics, Severity
from .pos import Pos, Range
from .tokens import Token
from .tokens import TokenType as T

_ID_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ID_CONT = _ID_START | frozenset("0123456789-")
_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")

#: Backslash escapes HCL recognises inside a quoted template. `$${` and `%%{`
#: are template escapes rather than backslash escapes and are handled inline.
_SIMPLE_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    '"': '"',
    "\\": "\\",
    "'": "'",
    "`": "`",
}

_TWO_CHAR_OPS = {
    "==": T.EQUAL_OP,
    "!=": T.NOT_EQUAL,
    "<=": T.LESS_THAN_EQ,
    ">=": T.GREATER_THAN_EQ,
    "&&": T.AND,
    "||": T.OR,
    "=>": T.FAT_ARROW,
    "::": T.DOUBLE_COLON,
}

_ONE_CHAR_OPS = {
    "{": T.OBRACE,
    "}": T.CBRACE,
    "[": T.OBRACK,
    "]": T.CBRACK,
    "(": T.OPAREN,
    ")": T.CPAREN,
    ",": T.COMMA,
    ".": T.DOT,
    ":": T.COLON,
    "?": T.QUESTION,
    "=": T.EQUAL,
    "+": T.PLUS,
    "-": T.MINUS,
    "*": T.STAR,
    "/": T.SLASH,
    "%": T.PERCENT,
    "!": T.BANG,
    "<": T.LESS_THAN,
    ">": T.GREATER_THAN,
}


#: Returned by the normal-mode scanner for input that produces no token at all
#: — a newline inside brackets. A sentinel rather than `None` so the return
#: type stays a Token and mypy keeps checking the call sites.
_SUPPRESSED = Token(T.INVALID, "", Range())


class _Mode(Enum):
    NORMAL = auto()
    TEMPLATE = auto()  # inside "…"
    HEREDOC = auto()  # inside <<EOF … EOF
    INTERP = auto()  # inside ${ … } or %{ … }


@dataclass(slots=True)
class _Frame:
    mode: _Mode
    #: HEREDOC only: the terminator identifier and whether `<<-` was used.
    marker: str = ""
    indented: bool = False
    #: HEREDOC only: the indent to strip, resolved when the terminator is seen.
    dedent: int = 0
    #: INTERP only: brace nesting, so an object literal inside an
    #: interpolation does not close the interpolation.
    brace_depth: int = 0
    #: HEREDOC only: whether the cursor sits at the start of a body line, which
    #: is where the terminator and the dedent apply.
    at_line_start: bool = True


class Lexer:
    """Produit le flux complet de jetons d'un fichier source.

    Travaille sur du `str` pour la gestion des caractères tout en suivant les
    décalages en octets contre l'encodage UTF-8, pour qu'une plage puisse
    redécouper les octets d'origine. Scanner des octets à la place ferait de
    chaque caractère multi-octets un cas particulier dans les scanneurs
    d'identifiants et de templates.
    """

    def __init__(self, src: bytes | str, filename: str = "", start: Pos | None = None) -> None:
        self.text = src.decode("utf-8", errors="replace") if isinstance(src, bytes) else src
        self.filename = filename
        self.i = 0
        self.line = start.line if start else 1
        self.column = start.column if start else 1
        self.byte = start.byte if start else 0
        self.diags = Diagnostics()
        self._stack: list[_Frame] = [_Frame(_Mode.NORMAL)]
        #: Depth of expression brackets, counted across the whole stream.
        #: Newlines are suppressed while non-zero.
        self._bracket_depth = 0
        #: Pre-computed dedent amounts, keyed by the offset the heredoc body
        #: starts at. Filled by a look-ahead when `<<-` is opened, because the
        #: terminator that sets the amount comes after the text it applies to.
        self._heredoc_dedents: dict[int, int] = {}

    # --- cursor -----------------------------------------------------------

    def _pos(self) -> Pos:
        return Pos(line=self.line, column=self.column, byte=self.byte)

    def _peek(self, ahead: int = 0) -> str:
        j = self.i + ahead
        return self.text[j] if j < len(self.text) else ""

    def _at_end(self) -> bool:
        return self.i >= len(self.text)

    def _starts_with(self, s: str) -> bool:
        return self.text.startswith(s, self.i)

    def _advance(self, n: int = 1) -> str:
        out: list[str] = []
        for _ in range(n):
            if self._at_end():
                break
            ch = self.text[self.i]
            out.append(ch)
            self.i += 1
            self.byte += len(ch.encode("utf-8"))
            if ch == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
        return "".join(out)

    def _tok(self, t: T, text: str, start: Pos, raw: str = "") -> Token:
        return Token(t, text, Range(self.filename, start, self._pos()), raw)

    def _err(self, summary: str, start: Pos, detail: str = "") -> None:
        self.diags.append(
            Diag(Severity.ERROR, summary, detail, Range(self.filename, start, self._pos()))
        )

    @property
    def _frame(self) -> _Frame:
        return self._stack[-1]

    # --- entry point ------------------------------------------------------

    def tokens(self) -> list[Token]:
        out: list[Token] = []
        while True:
            tok = self._next_token()
            if tok.type is T.COMMENT:
                continue
            out.append(tok)
            if tok.type is T.EOF:
                return out

    def _next_token(self) -> Token:
        # A loop rather than recursion: a suppressed newline (one inside
        # brackets) produces no token and has to try again, and a long list
        # written one element per line would otherwise recurse once per line.
        while True:
            mode = self._frame.mode
            if mode is _Mode.TEMPLATE:
                return self._next_template_token()
            if mode is _Mode.HEREDOC:
                return self._next_heredoc_token()
            tok = self._next_normal_token()
            if tok is not _SUPPRESSED:
                return tok

    # --- normal mode ------------------------------------------------------

    def _next_normal_token(self) -> Token:
        while not self._at_end() and self._peek() in " \t\r":
            self._advance()

        start = self._pos()
        if self._at_end():
            return self._tok(T.EOF, "", start)

        ch = self._peek()

        if ch == "\n":
            self._advance()
            if self._bracket_depth > 0:
                # Inside [] or (), a newline is whitespace: an expression may
                # wrap freely. Inside {} it is *not*, because both object
                # constructors and block bodies use it to separate items.
                return _SUPPRESSED
            return self._tok(T.NEWLINE, "\n", start)

        if ch == "#" or self._starts_with("//"):
            return self._scan_line_comment(start)
        if self._starts_with("/*"):
            return self._scan_block_comment(start)

        if ch == '"':
            self._advance()
            self._stack.append(_Frame(_Mode.TEMPLATE))
            return self._tok(T.OQUOTE, '"', start)

        if self._starts_with("<<"):
            return self._scan_heredoc_open(start)

        if ch in _DIGITS:
            return self._scan_number(start)
        if ch in _ID_START:
            return self._scan_ident(start)

        return self._scan_operator(start, ch)

    def _scan_line_comment(self, start: Pos) -> Token:
        buf: list[str] = []
        while not self._at_end() and self._peek() != "\n":
            buf.append(self._advance())
        return self._tok(T.COMMENT, "".join(buf), start)

    def _scan_block_comment(self, start: Pos) -> Token:
        buf = [self._advance(2)]
        while not self._at_end():
            if self._starts_with("*/"):
                buf.append(self._advance(2))
                return self._tok(T.COMMENT, "".join(buf), start)
            buf.append(self._advance())
        self._err("Unterminated block comment", start, "Expected */ before the end of file.")
        return self._tok(T.COMMENT, "".join(buf), start)

    def _scan_ident(self, start: Pos) -> Token:
        buf: list[str] = []
        while not self._at_end() and self._peek() in _ID_CONT:
            buf.append(self._advance())
        return self._tok(T.IDENT, "".join(buf), start)

    def _scan_number(self, start: Pos) -> Token:
        buf: list[str] = []
        while not self._at_end() and self._peek() in _DIGITS:
            buf.append(self._advance())
        if self._peek() == "." and self._peek(1) in _DIGITS:
            buf.append(self._advance())
            while not self._at_end() and self._peek() in _DIGITS:
                buf.append(self._advance())
        if self._peek() in ("e", "E"):
            saved = (self.i, self.byte, self.line, self.column)
            exp = [self._advance()]
            if self._peek() in ("+", "-"):
                exp.append(self._advance())
            if self._peek() in _DIGITS:
                while not self._at_end() and self._peek() in _DIGITS:
                    exp.append(self._advance())
                buf.extend(exp)
            else:
                # `1e` followed by a non-digit is a number then an identifier.
                self.i, self.byte, self.line, self.column = saved
        return self._tok(T.NUMBER, "".join(buf), start)

    def _scan_operator(self, start: Pos, ch: str) -> Token:
        if self._starts_with("..."):
            self._advance(3)
            return self._tok(T.ELLIPSIS, "...", start)

        two = self.text[self.i : self.i + 2]
        if two in _TWO_CHAR_OPS:
            self._advance(2)
            return self._tok(_TWO_CHAR_OPS[two], two, start)

        if ch in _ONE_CHAR_OPS:
            self._advance()
            t = _ONE_CHAR_OPS[ch]
            if t in (T.OBRACK, T.OPAREN):
                self._bracket_depth += 1
            elif t in (T.CBRACK, T.CPAREN):
                self._bracket_depth = max(0, self._bracket_depth - 1)
            elif t is T.OBRACE and self._frame.mode is _Mode.INTERP:
                self._frame.brace_depth += 1
            elif t is T.CBRACE:
                return self._close_brace(start)
            return self._tok(t, ch, start)

        bad = self._advance()
        self._err("Invalid character", start, f"The character {bad!r} is not valid in HCL.")
        return self._tok(T.INVALID, bad, start)

    def _close_brace(self, start: Pos) -> Token:
        """Un `}` ferme soit un objet ou un bloc, soit une interpolation.

        Seule la trame INTERP la plus intérieure n'ayant aucune accolade
        ouverte à elle peut être terminée — sinon `"${ {a = 1} }"` se
        terminerait à l'accolade fermante de l'objet intérieur et le reste de la
        chaîne serait lexé comme du code.
        """
        frame = self._frame
        if frame.mode is _Mode.INTERP:
            if frame.brace_depth > 0:
                frame.brace_depth -= 1
                return self._tok(T.CBRACE, "}", start)
            self._stack.pop()
            self._bracket_depth = max(0, self._bracket_depth - 1)
            return self._tok(T.TEMPLATE_SEQ_END, "}", start)
        return self._tok(T.CBRACE, "}", start)

    # --- quoted template mode --------------------------------------------

    def _next_template_token(self) -> Token:
        start = self._pos()

        if self._at_end():
            self._err("Unterminated string", start, "Expected a closing quote.")
            self._stack.pop()
            return self._tok(T.CQUOTE, "", start)

        if self._peek() == '"':
            self._advance()
            self._stack.pop()
            return self._tok(T.CQUOTE, '"', start)

        if self._starts_with("${"):
            self._advance(2)
            self._bracket_depth += 1
            self._stack.append(_Frame(_Mode.INTERP))
            return self._tok(T.TEMPLATE_INTERP, "${", start)

        if self._starts_with("%{"):
            self._advance(2)
            self._bracket_depth += 1
            self._stack.append(_Frame(_Mode.INTERP))
            return self._tok(T.TEMPLATE_CONTROL, "%{", start)

        out: list[str] = []
        raw: list[str] = []
        while not self._at_end():
            c = self._peek()
            if c == '"' or self._starts_with("${") or self._starts_with("%{"):
                break
            if self._starts_with("$${"):
                raw.append(self._advance(3))
                out.append("${")
                continue
            if self._starts_with("%%{"):
                raw.append(self._advance(3))
                out.append("%{")
                continue
            if c == "\\":
                raw.append(self._advance())
                out.append(self._scan_escape(start))
                continue
            if c == "\n":
                self._err(
                    "Invalid multi-line string", start, "Use a heredoc for text spanning lines."
                )
                break
            ch = self._advance()
            raw.append(ch)
            out.append(ch)
        return self._tok(T.QUOTED_LIT, "".join(out), start, "".join(raw))

    def _scan_escape(self, start: Pos) -> str:
        if self._at_end():
            self._err("Unterminated escape sequence", start)
            return ""
        c = self._advance()
        if c in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[c]
        if c == "u":
            return self._scan_unicode_escape(start, 4)
        if c == "U":
            return self._scan_unicode_escape(start, 8)
        self._err("Invalid escape sequence", start, f"\\{c} is not a valid escape sequence.")
        return c

    def _scan_unicode_escape(self, start: Pos, width: int) -> str:
        digits: list[str] = []
        for _ in range(width):
            if self._peek() in _HEX:
                digits.append(self._advance())
            else:
                break
        if len(digits) != width:
            self._err("Invalid unicode escape", start, f"Expected {width} hexadecimal digits.")
            return ""
        return chr(int("".join(digits), 16))

    # --- heredoc mode -----------------------------------------------------

    def _scan_heredoc_open(self, start: Pos) -> Token:
        self._advance(2)  # <<
        indented = False
        if self._peek() == "-":
            self._advance()
            indented = True

        marker_chars: list[str] = []
        while not self._at_end() and self._peek() in _ID_CONT:
            marker_chars.append(self._advance())
        marker = "".join(marker_chars)
        if not marker:
            self._err("Invalid heredoc", start, "Expected an identifier after <<.")
            return self._tok(T.INVALID, "<<", start)

        # Anything between the marker and the newline is not valid HCL, but
        # must not derail the rest of the file.
        while not self._at_end() and self._peek() != "\n":
            self._advance()
        if not self._at_end():
            self._advance()  # the newline that begins the body

        dedent = self._lookahead_dedent(marker) if indented else 0
        self._stack.append(
            _Frame(
                _Mode.HEREDOC, marker=marker, indented=indented, dedent=dedent, at_line_start=True
            )
        )
        return self._tok(T.OHEREDOC, marker, start, raw="-" if indented else "")

    def _lookahead_dedent(self, marker: str) -> int:
        """Détermine ce que `<<-` retire, sans déplacer le curseur.

        La règle de HCL est la plus petite indentation parmi les lignes du
        **corps**. L'indentation du terminateur est exclue — il ne fait pas
        partie du template — et cette exclusion est toute la subtilité. Dans

            policy = <<-POLICY
              {
                "Statement": [...]
              }
            POLICY

        l'indentation minimale du corps est 2 et celle du terminateur 0 ;
        inclure le terminateur ne retirerait rien et laisserait chaque ligne
        décalée. Ce texte est ce contre quoi `rules.iam_wildcard` fait sa
        recherche par expression régulière, donc la différence est une
        découverte qui se déclenche ou non.

        Calculé à l'avance, parce que le premier jeton littéral est émis bien
        avant que le terminateur ne soit atteint.
        """
        indents: list[int] = []
        for raw_line in self.text[self.i :].split("\n"):
            stripped = raw_line.strip()
            if stripped == marker:
                break
            if stripped:
                indents.append(len(raw_line) - len(raw_line.lstrip()))
        return min(indents) if indents else 0

    def _next_heredoc_token(self) -> Token:
        frame = self._frame
        start = self._pos()

        if self._at_end():
            self._err(
                "Unterminated heredoc",
                start,
                f"Expected a line containing only {frame.marker} to close the heredoc.",
            )
            self._stack.pop()
            return self._tok(T.CHEREDOC, "", start)

        if frame.at_line_start:
            line_end = self.text.find("\n", self.i)
            line = self.text[self.i :] if line_end < 0 else self.text[self.i : line_end]
            if line.strip() == frame.marker:
                self._advance(len(line))
                # The newline after the terminator is deliberately left in the
                # stream: it is the NEWLINE that terminates the enclosing
                # attribute. Consuming it here would push the attribute's end
                # range onto the following line and put every heredoc-valued
                # attribute one line further down than hcl reports it.
                self._stack.pop()
                return self._tok(T.CHEREDOC, frame.marker, start)
            if frame.dedent:
                # Consume the stripped indent without emitting it. It stays
                # inside the token stream's byte accounting, so ranges after
                # this point remain true to the file.
                to_skip = 0
                while to_skip < frame.dedent and self._peek(to_skip) in " \t":
                    to_skip += 1
                if to_skip:
                    self._advance(to_skip)
                    start = self._pos()
            frame.at_line_start = False

        if self._starts_with("${"):
            self._advance(2)
            self._bracket_depth += 1
            self._stack.append(_Frame(_Mode.INTERP))
            return self._tok(T.TEMPLATE_INTERP, "${", start)

        if self._starts_with("%{"):
            self._advance(2)
            self._bracket_depth += 1
            self._stack.append(_Frame(_Mode.INTERP))
            return self._tok(T.TEMPLATE_CONTROL, "%{", start)

        out: list[str] = []
        while not self._at_end():
            if self._starts_with("$${"):
                self._advance(3)
                out.append("${")
                continue
            if self._starts_with("%%{"):
                self._advance(3)
                out.append("%{")
                continue
            if self._starts_with("${") or self._starts_with("%{"):
                break
            ch = self._advance()
            out.append(ch)
            if ch == "\n":
                frame.at_line_start = True
                break
        return self._tok(T.QUOTED_LIT, "".join(out), start)


def tokenize(src: bytes | str, filename: str = "") -> tuple[list[Token], Diagnostics]:
    """Découpe tout un fichier en jetons. L'analyseur appelle ceci puis
    travaille sur la liste."""
    lx = Lexer(src, filename)
    return lx.tokens(), lx.diags
