"""Analyseur à descente récursive pour HCL2 : transforme le flux de jetons en
l'AST de `ast.py`.

Grammaire implémentée, celle de la syntaxe native HCL :

    Body        = (Attribute | Block)*
    Attribute   = Identifier "=" Expression Newline
    Block       = Identifier (StringLit | Identifier)* "{" Newline Body "}" Newline
    Expression  = Conditional
    Conditional = Or ("?" Expression ":" Expression)?
    Or          = And ("||" And)*
    And         = Equality ("&&" Equality)*
    Equality    = Comparison (("==" | "!=") Comparison)*
    Comparison  = Additive (("<" | "<=" | ">" | ">=") Additive)*
    Additive    = Multiplicative (("+" | "-") Multiplicative)*
    Multiplicative = Unary (("*" | "/" | "%") Unary)*
    Unary       = ("!" | "-")? Postfix
    Postfix     = Primary (GetAttr | Index | Splat | Call)*

Sur erreur, enregistre un diagnostic puis **se rattrape au prochain saut de
ligne ou à l'accolade fermante** plutôt que de s'arrêter, comme hclsyntax : un
attribut malformé ne doit pas coûter les autres ressources du fichier.
`parse_config` rend ce qu'il a construit avec les diagnostics ; c'est
`parser.parse_file` qui décide qu'une erreur rend le fichier illisible.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

from . import values as cty
from .ast import (
    Attribute,
    BinaryOpExpr,
    Block,
    Body,
    ConditionalExpr,
    Expression,
    File,
    ForExpr,
    FunctionCallExpr,
    IndexExpr,
    LiteralValueExpr,
    ObjectConsExpr,
    ObjectConsItem,
    ObjectConsKeyExpr,
    ParenthesesExpr,
    RelativeTraversalExpr,
    ScopeTraversalExpr,
    SplatExpr,
    TemplateExpr,
    TemplateWrapExpr,
    TupleConsExpr,
    UnaryOpExpr,
)
from .diagnostics import Diagnostic, Diagnostics, Severity
from .lexer import Lexer
from .pos import Pos, Range
from .tokens import Token
from .tokens import TokenType as T
from .traversal import Step, Traversal, TraverseAttr, TraverseIndex, TraverseRoot

_BINARY_LEVELS: list[tuple[T, ...]] = [
    (T.OR,),
    (T.AND,),
    (T.EQUAL_OP, T.NOT_EQUAL),
    (T.LESS_THAN, T.LESS_THAN_EQ, T.GREATER_THAN, T.GREATER_THAN_EQ),
    (T.PLUS, T.MINUS),
    (T.STAR, T.SLASH, T.PERCENT),
]

_OP_TEXT = {
    T.OR: "||",
    T.AND: "&&",
    T.EQUAL_OP: "==",
    T.NOT_EQUAL: "!=",
    T.LESS_THAN: "<",
    T.LESS_THAN_EQ: "<=",
    T.GREATER_THAN: ">",
    T.GREATER_THAN_EQ: ">=",
    T.PLUS: "+",
    T.MINUS: "-",
    T.STAR: "*",
    T.SLASH: "/",
    T.PERCENT: "%",
}

_KEYWORD_VALUES = {
    "true": cty.TRUE,
    "false": cty.FALSE,
    "null": cty.NULL_VAL,
}


class Parser:
    def __init__(self, tokens: list[Token], filename: str) -> None:
        self.toks = tokens
        self.filename = filename
        self.i = 0
        self.diags = Diagnostics()

    # --- token cursor -----------------------------------------------------

    def _peek(self, ahead: int = 0) -> Token:
        j = self.i + ahead
        return self.toks[j] if j < len(self.toks) else self.toks[-1]

    def _next(self) -> Token:
        tok = self._peek()
        if tok.type is not T.EOF:
            self.i += 1
        return tok

    def _check(self, *types: T) -> bool:
        return self._peek().type in types

    def _match(self, *types: T) -> Token | None:
        if self._check(*types):
            return self._next()
        return None

    def _skip_newlines(self) -> None:
        while self._check(T.NEWLINE):
            self._next()

    def _error(self, summary: str, detail: str, tok: Token | None = None) -> None:
        subject = tok.range if tok else self._peek().range
        self.diags.append(Diagnostic(Severity.ERROR, summary, detail, subject))

    def _here(self) -> Range:
        return self._peek().range

    def _empty_range(self) -> Range:
        p = self._peek().range.start
        return Range(self.filename, p, p)

    # --- bodies -----------------------------------------------------------

    def parse_body(self, end: T = T.EOF) -> Body:
        body = Body(src_range=self._here())
        start_pos = self._peek().range.start
        while True:
            self._skip_newlines()
            tok = self._peek()
            if tok.type is end or tok.type is T.EOF:
                break

            # Où en étions-nous avant de tenter quoi que ce soit ? Comparé en
            # fin de tour, c'est la garantie que cette boucle se termine.
            #
            # Elle ne se terminait pas. `_recover_to_newline` rend la main sans
            # rien consommer devant un `}` à profondeur nulle — ce qui est juste
            # quand on rattrape à l'intérieur d'un bloc, dont le `}` est la
            # borne que l'appelant attend, et faux ici : au niveau racine, `end`
            # vaut EOF, donc rien ne s'arrête sur une accolade fermante orpheline
            # et le tour suivant retrouve exactement le même jeton.
            #
            # Le symptôme n'était pas un mauvais diagnostic mais un scanner qui
            # ne rend jamais la main. Le déclencheur d'origine est corrigé
            # au-dessus (`_parse_for`), et il n'a pas à être le dernier : un
            # analyseur écrit à la main aura d'autres trous, et le pire d'entre
            # eux doit rester « une erreur signalée », jamais « la CI du client
            # tourne jusqu'à son délai ».
            before = self.i

            if tok.type is not T.IDENT:
                self._error(
                    "Argument or block definition required",
                    "An argument or block definition is required here.",
                    tok,
                )
                self._recover_to_newline()
            else:
                self._parse_body_item(body)

            if self.i == before:
                # Personne n'a avancé. On consomme le jeton fautif nous-mêmes,
                # sans second diagnostic : celui qui vient d'être posé décrit
                # déjà le problème, et en ajouter un par jeton noierait le
                # rapport.
                self._next()
        body.src_range = Range(self.filename, start_pos, self._peek().range.end)
        return body

    def _parse_body_item(self, body: Body) -> None:
        ident = self._next()
        if self._check(T.EQUAL):
            self._parse_attribute(body, ident)
        elif self._check(T.OQUOTE, T.IDENT, T.OBRACE):
            self._parse_block(body, ident)
        else:
            self._error(
                "Argument or block definition required",
                f"An argument definition (=) or a block body ({{) must follow {ident.text!r}.",
                self._peek(),
            )
            self._recover_to_newline()

    def _parse_attribute(self, body: Body, ident: Token) -> None:
        equals = self._next()  # =
        expr = self.parse_expression()
        # The attribute ends where its *expression* ends, not where the next
        # token starts. Comments are dropped from the stream, so the next token
        # after `threshold = 70 # allows ~87` is the newline past the comment —
        # taking that as the end would fold the comment text into the
        # attribute's range. `rules.iam_wildcard` slices the raw source over
        # this range and regex-matches it, so a comment mentioning
        # `Action = "*"` would become a finding about a policy that grants
        # nothing. Matches hclsyntax, which spans name..expr.
        end = expr.range.end
        if not self._check(T.NEWLINE, T.EOF, T.CBRACE):
            self._error(
                "Missing newline after argument",
                "An argument definition must end with a newline.",
                self._peek(),
            )
            self._recover_to_newline()
        attribute = Attribute(
            name=ident.text,
            expr=expr,
            src_range=Range(self.filename, ident.range.start, end),
            name_range=ident.range,
            equals_range=equals.range,
        )
        if ident.text in body.attributes:
            self._error(
                "Duplicate argument",
                f"Argument {ident.text!r} was already set in this block.",
                ident,
            )
        body.attributes[ident.text] = attribute

    def _parse_block(self, body: Body, ident: Token) -> None:
        labels: list[str] = []
        label_ranges: list[Range] = []
        while True:
            if self._check(T.OQUOTE):
                text, rng = self._parse_quoted_label()
                labels.append(text)
                label_ranges.append(rng)
            elif self._check(T.IDENT):
                tok = self._next()
                labels.append(tok.text)
                label_ranges.append(tok.range)
            else:
                break

        open_brace = self._match(T.OBRACE)
        if open_brace is None:
            self._error(
                "Invalid block definition", "A block must be followed by '{'.", self._peek()
            )
            self._recover_to_newline()
            return

        inner = self.parse_body(end=T.CBRACE)
        close_brace = self._match(T.CBRACE)
        if close_brace is None:
            self._error("Unclosed block", f"The {ident.text!r} block has no closing brace.", ident)
            close_brace = self._peek()

        body.blocks.append(
            Block(
                type=ident.text,
                labels=labels,
                body=inner,
                type_range=ident.range,
                label_ranges=label_ranges,
                open_brace_range=open_brace.range,
                close_brace_range=close_brace.range,
            )
        )

    def _parse_quoted_label(self) -> tuple[str, Range]:
        """Une étiquette de bloc est une chaîne entre guillemets sans interpolation.

        Une étiquette interpolée — `resource "aws_${x}" "y"` — n'est pas du
        Terraform valide ; le texte est pris tel qu'écrit pour que le bloc s'analyse
        quand même et que le reste du fichier soit tout de même scanné.
        """
        open_q = self._next()  # OQUOTE
        parts: list[str] = []
        while not self._check(T.CQUOTE, T.EOF):
            tok = self._next()
            if tok.type is T.QUOTED_LIT:
                parts.append(tok.text)
            elif tok.type in (T.TEMPLATE_INTERP, T.TEMPLATE_CONTROL):
                depth = 1
                while depth > 0 and not self._check(T.EOF):
                    nxt = self._next()
                    if nxt.type in (T.TEMPLATE_INTERP, T.TEMPLATE_CONTROL):
                        depth += 1
                    elif nxt.type is T.TEMPLATE_SEQ_END:
                        depth -= 1
        close_q = self._match(T.CQUOTE) or self._peek()
        return "".join(parts), Range(self.filename, open_q.range.start, close_q.range.end)

    def _recover_to_newline(self) -> None:
        """Avance jusqu'au prochain saut de ligne à profondeur d'accolades nulle.

        C'est ce rattrapage qui fait qu'un mauvais attribut ne coûte qu'un attribut.
        Sans lui, un caractère égaré dans un module de 400 lignes ferait tomber
        toutes les ressources qui le suivent, et le scan reviendrait propre pour la
        mauvaise raison.
        """
        depth = 0
        while True:
            tok = self._peek()
            if tok.type is T.EOF:
                return
            if tok.type is T.NEWLINE and depth <= 0:
                self._next()
                return
            if tok.type is T.CBRACE and depth <= 0:
                return
            if tok.type in (T.OBRACE, T.OBRACK, T.OPAREN):
                depth += 1
            elif tok.type in (T.CBRACE, T.CBRACK, T.CPAREN):
                depth -= 1
            self._next()

    # --- expressions ------------------------------------------------------

    def parse_expression(self) -> Expression:
        return self._parse_conditional()

    def _parse_conditional(self) -> Expression:
        cond = self._parse_binary(0)
        if not self._check(T.QUESTION):
            return cond
        self._next()
        true_result = self.parse_expression()
        if not self._match(T.COLON):
            self._error(
                "Missing false expression in conditional",
                "A conditional expression must have a ':' and a false result.",
                self._peek(),
            )
            return cond
        false_result = self.parse_expression()
        return ConditionalExpr(
            condition=cond,
            true_result=true_result,
            false_result=false_result,
            range=cond.range.merge(false_result.range),
        )

    def _parse_binary(self, level: int) -> Expression:
        if level >= len(_BINARY_LEVELS):
            return self._parse_unary()
        ops = _BINARY_LEVELS[level]
        lhs = self._parse_binary(level + 1)
        while self._check(*ops):
            op_tok = self._next()
            rhs = self._parse_binary(level + 1)
            lhs = BinaryOpExpr(
                op=_OP_TEXT[op_tok.type],
                lhs=lhs,
                rhs=rhs,
                range=lhs.range.merge(rhs.range),
            )
        return lhs

    def _parse_unary(self) -> Expression:
        if self._check(T.BANG, T.MINUS):
            op_tok = self._next()
            operand = self._parse_unary()
            op = "!" if op_tok.type is T.BANG else "-"
            return UnaryOpExpr(op=op, operand=operand, range=op_tok.range.merge(operand.range))
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            if self._check(T.DOT):
                expr = self._parse_get_attr(expr)
            elif self._check(T.OBRACK):
                expr = self._parse_index(expr)
            elif self._check(T.OPAREN) and isinstance(expr, ScopeTraversalExpr):
                expr = self._parse_call_on(expr)
            else:
                return expr

    def _parse_get_attr(self, expr: Expression) -> Expression:
        self._next()  # .
        if self._check(T.STAR):
            star = self._next()
            return SplatExpr(source=expr, range=expr.range.merge(star.range))
        tok = self._next()
        if tok.type not in (T.IDENT, T.NUMBER):
            self._error("Invalid attribute name", "An attribute name is required after '.'.", tok)
            return expr
        step: Step
        if tok.type is T.NUMBER:
            # `list.0` is HCL's legacy index spelling.
            step = TraverseIndex(cty.number_val(tok.text), tok.range)
        else:
            step = TraverseAttr(tok.text, tok.range)

        if isinstance(expr, ScopeTraversalExpr):
            expr.traversal.append(step)
            expr.range = expr.range.merge(tok.range)
            return expr
        if isinstance(expr, RelativeTraversalExpr):
            expr.traversal.append(step)
            expr.range = expr.range.merge(tok.range)
            return expr
        return RelativeTraversalExpr(
            source=expr, traversal=Traversal([step]), range=expr.range.merge(tok.range)
        )

    def _parse_index(self, expr: Expression) -> Expression:
        self._next()  # [
        if self._check(T.STAR):
            self._next()
            close = self._match(T.CBRACK) or self._peek()
            return SplatExpr(source=expr, range=expr.range.merge(close.range))
        key = self.parse_expression()
        matched = self._match(T.CBRACK)
        if matched is None:
            self._error("Missing close bracket", "Expected ']' to close the index.", self._peek())
        close = matched if matched is not None else self._peek()
        return IndexExpr(collection=expr, key=key, range=expr.range.merge(close.range))

    def _parse_call_on(self, callee: ScopeTraversalExpr) -> Expression:
        """Un appel dont le nom est arrivé sous forme de traversée —
        `jsonencode(...)`, `provider::ns::fn(...)`."""
        name = callee.traversal.render(max_steps=8) or ""
        self._next()  # (
        args: list[Expression] = []
        expand_final = False
        while not self._check(T.CPAREN, T.EOF):
            self._skip_newlines()
            if self._check(T.CPAREN):
                break
            args.append(self.parse_expression())
            self._skip_newlines()
            if self._check(T.ELLIPSIS):
                self._next()
                expand_final = True
            if not self._match(T.COMMA):
                break
            self._skip_newlines()
        close = self._match(T.CPAREN)
        if close is None:
            self._error(
                "Missing close parenthesis", "Expected ')' to close the call.", self._peek()
            )
            close = self._peek()
        return FunctionCallExpr(
            name=name, args=args, expand_final=expand_final, range=callee.range.merge(close.range)
        )

    def _parse_primary(self) -> Expression:
        tok = self._peek()

        if tok.type is T.NUMBER:
            self._next()
            return LiteralValueExpr(_number_literal(tok, self), tok.range)

        if tok.type is T.OQUOTE:
            return self._parse_quoted_template()

        if tok.type is T.OHEREDOC:
            return self._parse_heredoc()

        if tok.type is T.OBRACK:
            return self._parse_tuple()

        if tok.type is T.OBRACE:
            return self._parse_object()

        if tok.type is T.OPAREN:
            self._next()
            inner = self.parse_expression()
            close = self._match(T.CPAREN)
            if close is None:
                self._error("Missing close parenthesis", "Expected ')'.", self._peek())
                close = self._peek()
            return ParenthesesExpr(inner, tok.range.merge(close.range))

        if tok.type is T.IDENT:
            if tok.text in _KEYWORD_VALUES:
                self._next()
                return LiteralValueExpr(_KEYWORD_VALUES[tok.text], tok.range)
            return self._parse_variable()

        self._error("Invalid expression", "Expected the start of an expression here.", tok)
        self._next()
        return LiteralValueExpr(cty.DYNAMIC_VAL, tok.range)

    def _parse_variable(self) -> Expression:
        """Un identifiant, ou un nom de fonction avec espace de noms.

        `provider::aws::arn_parse(...)` — les fonctions définies par un fournisseur,
        Terraform 1.8 et plus — est lexé en IDENT `::` IDENT `::` IDENT. Le tout est
        un seul nom, donc les segments `::` sont repliés dans la racine ici plutôt
        que de devenir des étapes de traversée ; les traiter comme des étapes
        rendrait l'appelé irrésoluble et l'expression inanalysable.
        """
        tok = self._next()
        name = tok.text
        end_range = tok.range
        while self._check(T.DOUBLE_COLON):
            self._next()
            part = self._match(T.IDENT)
            if part is None:
                self._error(
                    "Invalid function name",
                    "A name is required after '::'.",
                    self._peek(),
                )
                break
            name += "::" + part.text
            end_range = part.range

        full_range = tok.range.merge(end_range)
        return ScopeTraversalExpr(
            traversal=Traversal([TraverseRoot(name, full_range)]), range=full_range
        )

    # --- templates --------------------------------------------------------

    def _parse_quoted_template(self) -> Expression:
        open_q = self._next()  # OQUOTE
        parts, close = self._parse_template_parts(T.CQUOTE)
        rng = Range(self.filename, open_q.range.start, close.range.end)
        return _template_expr(parts, rng)

    def _parse_heredoc(self) -> Expression:
        open_h = self._next()  # OHEREDOC
        parts, close = self._parse_template_parts(T.CHEREDOC)
        rng = Range(self.filename, open_h.range.start, close.range.end)
        # A heredoc is always a string, even when it holds one interpolation:
        # `<<EOF\n${x}\nEOF` carries the trailing newline, so it cannot pass
        # the wrapped value through the way `"${x}"` does.
        return TemplateExpr(parts=parts, range=rng)

    def _parse_template_parts(self, end: T) -> tuple[list[Expression], Token]:
        parts: list[Expression] = []
        while True:
            tok = self._peek()
            if tok.type is end:
                return parts, self._next()
            if tok.type is T.EOF:
                self._error("Unterminated template", "Expected the template to be closed.", tok)
                return parts, tok
            if tok.type is T.QUOTED_LIT:
                self._next()
                parts.append(LiteralValueExpr(cty.string_val(tok.text), tok.range))
                continue
            if tok.type is T.TEMPLATE_INTERP:
                self._next()
                inner = self.parse_expression()
                seq_end = self._match(T.TEMPLATE_SEQ_END)
                if seq_end is None:
                    self._error(
                        "Unterminated interpolation",
                        "Expected '}' to close the interpolation sequence.",
                        self._peek(),
                    )
                    seq_end = self._peek()
                parts.append(inner)
                continue
            if tok.type is T.TEMPLATE_CONTROL:
                # `%{ if … }` / `%{ for … }`. Directives are consumed so the
                # rest of the file parses; the template as a whole becomes
                # unevaluable, which is the honest answer — the output depends
                # on a condition the scanner cannot resolve.
                self._skip_template_directive()
                parts.append(LiteralValueExpr(cty.DYNAMIC_VAL, tok.range))
                continue
            # Anything else inside a template is a lexer-level problem already
            # reported; consume it so the loop terminates.
            self._next()

    def _skip_template_directive(self) -> None:
        self._next()  # %{
        depth = 1
        while depth > 0 and not self._check(T.EOF):
            tok = self._next()
            if tok.type in (T.TEMPLATE_INTERP, T.TEMPLATE_CONTROL):
                depth += 1
            elif tok.type is T.TEMPLATE_SEQ_END:
                depth -= 1

    # --- collections ------------------------------------------------------

    def _parse_tuple(self) -> Expression:
        open_b = self._next()  # [
        self._skip_newlines()

        if self._is_for_start():
            return self._parse_for(open_b, is_object=False)

        exprs: list[Expression] = []
        while not self._check(T.CBRACK, T.EOF):
            self._skip_newlines()
            if self._check(T.CBRACK):
                break
            exprs.append(self.parse_expression())
            self._skip_newlines()
            if not self._match(T.COMMA):
                break
            self._skip_newlines()
        close = self._match(T.CBRACK)
        if close is None:
            self._error("Missing close bracket", "Expected ']' to close the tuple.", self._peek())
            close = self._peek()
        return TupleConsExpr(exprs=exprs, range=open_b.range.merge(close.range))

    def _parse_object(self) -> Expression:
        open_b = self._next()  # {
        self._skip_newlines()

        if self._is_for_start():
            return self._parse_for(open_b, is_object=True)

        items: list[ObjectConsItem] = []
        while not self._check(T.CBRACE, T.EOF):
            self._skip_newlines()
            if self._check(T.CBRACE):
                break
            key_expr = self.parse_expression()
            key = ObjectConsKeyExpr(wrapped=key_expr, range=key_expr.range)
            if not self._match(T.EQUAL, T.COLON):
                self._error(
                    "Missing key/value separator",
                    "Expected '=' or ':' after an object key.",
                    self._peek(),
                )
                self._recover_to_newline()
                continue
            value_expr = self.parse_expression()
            items.append(ObjectConsItem(key=key, value_expr=value_expr))
            self._skip_newlines()
            self._match(T.COMMA)
            self._skip_newlines()
        close = self._match(T.CBRACE)
        if close is None:
            self._error("Missing close brace", "Expected '}' to close the object.", self._peek())
            close = self._peek()
        return ObjectConsExpr(items=items, range=open_b.range.merge(close.range))

    def _is_for_start(self) -> bool:
        tok = self._peek()
        return tok.type is T.IDENT and tok.text == "for"

    def _parse_for(self, open_tok: Token, is_object: bool) -> Expression:
        """Analyse une compréhension `for` juste assez pour la consommer
        correctement.

        Le résultat ne s'évalue jamais (voir ForExpr), donc l'intérêt de l'analyser
        précisément est structurel : les jetons doivent être consommés jusqu'au
        crochet correspondant, sinon tout ce qui suit dans le fichier s'analyse de
        travers.
        """
        self._next()  # 'for'
        key_var = ""
        value_var = ""
        first = self._match(T.IDENT)
        if first is not None:
            value_var = first.text
        if self._match(T.COMMA):
            second = self._match(T.IDENT)
            if second is not None:
                key_var, value_var = value_var, second.text
        if not self._match(T.IDENT):  # 'in'
            self._error(
                "Invalid for expression", "Expected 'in' after the for variables.", self._peek()
            )
        collection = self.parse_expression()
        self._skip_newlines()
        if not self._match(T.COLON):
            self._error(
                "Invalid for expression", "Expected ':' after the collection.", self._peek()
            )

        # Les sauts de ligne sont sans signification à l'intérieur de crochets,
        # et c'est exactement là que `terraform fmt` en met : passé une
        # certaine longueur, il coupe la ligne après le `:` d'une compréhension
        # et remet la clé en dessous.
        #
        # Cette absence-là ne produisait pas une découverte manquée mais une
        # BOUCLE INFINIE. L'expression s'analysait de travers, laissait des
        # jetons orphelins derrière elle, et la boucle de `parse_body` tournait
        # ensuite sans jamais avancer — le scanner ne rendait plus la main, dans
        # la CI d'un client, jusqu'au délai du job. Trouvé sur notre propre
        # `infra/terraform/cron_lambda.tf`.
        self._skip_newlines()

        first_expr = self.parse_expression()
        key_expr: Expression | None = None
        value_expr = first_expr
        group = False
        self._skip_newlines()
        if is_object and self._match(T.FAT_ARROW):
            self._skip_newlines()
            key_expr = first_expr
            value_expr = self.parse_expression()
            self._skip_newlines()
            if self._match(T.ELLIPSIS):
                group = True

        condition: Expression | None = None
        self._skip_newlines()
        if self._check(T.IDENT) and self._peek().text == "if":
            self._next()
            condition = self.parse_expression()

        self._skip_newlines()
        close = self._match(T.CBRACE if is_object else T.CBRACK)
        if close is None:
            self._error(
                "Missing close bracket", "Expected the for expression to be closed.", self._peek()
            )
            close = self._peek()
        return ForExpr(
            collection=collection,
            key_var=key_var,
            value_var=value_var,
            key_expr=key_expr,
            value_expr=value_expr,
            condition=condition,
            is_object=is_object,
            group=group,
            range=open_tok.range.merge(close.range),
        )


def _template_expr(parts: list[Expression], rng: Range) -> Expression:
    """Construit le bon nœud pour un template entre guillemets.

    Un template vide est la chaîne vide ; un template fait d'exactement une
    interpolation laisse passer sa valeur avec son propre type (le cas
    « template wrap » de HCL, qui garde `"${var.n}"` numérique) ; tout le reste
    concatène.
    """
    if not parts:
        return LiteralValueExpr(cty.EMPTY_STRING, rng)
    if len(parts) == 1 and not isinstance(parts[0], LiteralValueExpr):
        return TemplateWrapExpr(wrapped=parts[0], range=rng)
    return TemplateExpr(parts=parts, range=rng)


def _number_literal(tok: Token, p: Parser) -> cty.Value:
    try:
        return cty.number_val(Decimal(tok.text))
    except (InvalidOperation, ValueError):  # pragma: no cover - lexer guarantees the shape
        p._error("Invalid number", f"{tok.text!r} is not a valid number.", tok)
        return cty.DYNAMIC_VAL


def parse_config(
    source: bytes | str, filename: str = "", start: Pos | None = None
) -> tuple[File, Diagnostics]:
    """Analyse un fichier HCL entier. À l'image de `hclsyntax.ParseConfig`.

    Rend le fichier *et* les diagnostics ; un fichier comportant des erreurs
    porte quand même tout ce qui s'est analysé proprement. Les appelants qui
    veulent du tout-ou-rien vérifient eux-mêmes `diags.has_errors()`, ce que
    fait `parser.parse_file`.
    """
    raw = source.encode("utf-8") if isinstance(source, str) else source
    lexer = Lexer(raw, filename, start)
    tokens = lexer.tokens()
    p = Parser(tokens, filename)
    body = p.parse_body(end=T.EOF)
    diags = Diagnostics(lexer.diags)
    diags.extend(p.diags)
    return File(body=body, source=raw, filename=filename), diags
