#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import string

from enum import IntEnum
from typing import Callable

ESC_IDLE    = 0     # escape parser is idleing
ESC_ISTR    = 1     # currently inside a string
ESC_BKSL    = 2     # encountered backslash, prepare for escape sequences
ESC_HEX0    = 3     # expect the first hexadecimal character of a "\x" escape
ESC_HEX1    = 4     # expect the second hexadecimal character of a "\x" escape
ESC_OCT1    = 5     # expect the second octal character of a "\000" escape
ESC_OCT2    = 6     # expect the third octal character of a "\000" escape

class Line:
    @staticmethod
    def remove_comments(line: str, *, st: str = 'normal') -> str:
        for i, ch in enumerate(line):
            if   st == 'normal' and ch == '/'  : st = 'slcomm'
            elif st == 'normal' and ch == '\"' : st = 'string'
            elif st == 'normal' and ch == ';'  : return line[:i].strip()
            elif st == 'slcomm' and ch == '/'  : return line[:i - 1].strip()
            elif st == 'slcomm'                : st = 'normal'
            elif st == 'string' and ch == '\"' : st = 'normal'
            elif st == 'string' and ch == '\\' : st = 'escape'
            elif st == 'escape'                : st = 'string'
        else:
            return line.strip()

class TokenKind(IntEnum):
    End     = 0
    Reg     = 1
    Imm     = 2
    Num     = 3
    Name    = 4
    Punc    = 5

class Token:
    val: int | str
    tag: TokenKind

    def __init__(self, tag: TokenKind, val: int | str):
        self.val = val
        self.tag = tag

    @property
    def int_value(self) -> int:
        if not isinstance(self.val, int):
            raise TypeError('value is not int')
        else:
            return self.val

    @property
    def str_value(self) -> str:
        if not isinstance(self.val, str):
            raise TypeError('value is not str')
        else:
            return self.val

    @classmethod
    def end(cls):
        return cls(TokenKind.End, '')

    @classmethod
    def reg(cls, reg: str):
        return cls(TokenKind.Reg, reg)

    @classmethod
    def imm(cls, imm: int):
        return cls(TokenKind.Imm, imm)

    @classmethod
    def num(cls, num: int):
        return cls(TokenKind.Num, num)

    @classmethod
    def name(cls, name: str):
        return cls(TokenKind.Name, name)

    @classmethod
    def punc(cls, punc: str):
        return cls(TokenKind.Punc, punc)

    def __repr__(self):
        match self.tag:
            case TokenKind.End  : return '<END>'
            case TokenKind.Reg  : return '<REG %s>' % self.val
            case TokenKind.Imm  : return '<IMM %d>' % self.val
            case TokenKind.Num  : return '<NUM %d>' % self.val
            case TokenKind.Name : return '<NAME %s>' % repr(self.val)
            case TokenKind.Punc : return '<PUNC %s>' % repr(self.val)
            case _              : return '<UNK:%d %r>' % (self.tag, self.val)

class Command:
    cmd  : str
    args : list[str | bytes]

    def __init__(self, cmd: str, args: list[str | bytes]):
        self.cmd  = cmd
        self.args = args

    def __str__(self) -> str:
        if not self.args:
            return self.cmd
        else:
            return self.cmd + ' ' + ', '.join(repr(v)[1:] if isinstance(v, bytes) else v for v in self.args)

    def as_int(self, i: int) -> int:
        val = self.as_str(i)
        return int(val, 8 if val.isdigit() and val.startswith('0') else 0)

    def as_str(self, i: int) -> str:
        return self._check_str(self.args[i])

    def as_bytes(self, i: int) -> bytes:
        return self._check_bytes(self.args[i])

    @staticmethod
    def _check_str(v: str | bytes) -> str:
        if not isinstance(v, str):
            raise TypeError('value is not str')
        else:
            return v

    @staticmethod
    def _check_bytes(v: str | bytes) -> bytes:
        if not isinstance(v, bytes):
            raise TypeError('value is not bytes')
        else:
            return v

    @classmethod
    def parse(cls, src: str) -> 'Command':
        val = src.split(None, 1)
        cmd = val[0]

        # no parameters
        if len(val) == 1:
            return cls(cmd, [])

        # extract the argument string
        idx = 0
        esc = 0
        pos = None
        args = []
        vstr = val[1]

        # scan through the whole string
        while idx < len(vstr):
            nch = vstr[idx]
            idx += 1

            # mark the start of the argument
            if pos is None:
                pos = idx - 1

            # encountered the delimiter outside of a string
            if nch == ',' and esc == ESC_IDLE:
                pos, p = None, pos
                args.append(vstr[p:idx - 1].strip())

            # start of a string
            elif nch == '"' and esc == ESC_IDLE:
                esc = ESC_ISTR

            # end of string
            elif nch == '"' and esc == ESC_ISTR:
                esc = ESC_IDLE
                pos, p = None, pos
                args.append(vstr[p:idx].strip()[1:-1].encode('utf-8').decode('unicode_escape').encode('latin1'))

            # escape characters
            elif nch == '\\' and esc == ESC_ISTR:
                esc = ESC_BKSL

            # hexadecimal escape characters (3 chars)
            elif esc == ESC_BKSL and nch == 'x':
                esc = ESC_HEX0

            # octal escape characters (3 chars)
            elif esc == ESC_BKSL and nch in string.octdigits:
                esc = ESC_OCT1

            # generic escape characters (single char)
            elif esc == ESC_BKSL and nch in ('a', 'b', 'f', 'r', 'n', 't', 'v', '"', '\\'):
                esc = ESC_ISTR

            # invalid escape sequence
            elif esc == ESC_BKSL:
                raise SyntaxError('invalid escape character: ' + repr(nch))

            # normal characters, simply advance to the next character
            elif esc in (ESC_IDLE, ESC_ISTR):
                pass

            # hexadecimal escape characters
            elif esc in (ESC_HEX0, ESC_HEX1) and nch.lower() in string.hexdigits:
                esc = ESC_HEX1 if esc == ESC_HEX0 else ESC_ISTR

            # invalid hexadecimal character
            elif esc in (ESC_HEX0, ESC_HEX1):
                raise SyntaxError('invalid hexdecimal character: ' + repr(nch))

            # octal escape characters
            elif esc in (ESC_OCT1, ESC_OCT2) and nch.lower() in string.octdigits:
                esc = ESC_OCT2 if esc == ESC_OCT1 else ESC_ISTR

            # at most 3 octal digits
            elif esc in (ESC_OCT1, ESC_OCT2):
                esc = ESC_ISTR

            # illegal state, should not happen
            else:
                raise RuntimeError('illegal state: %d' % esc)

        # check for the last argument
        if pos is None:
            return cls(cmd, args)

        # add the last argument and build the command
        args.append(vstr[pos:].strip())
        return cls(cmd, args)

class Expression:
    pos: int
    src: str

    def __init__(self, src: str):
        self.pos = 0
        self.src = src

    @property
    def _ch(self) -> str:
        return self.src[self.pos]

    @property
    def _eof(self) -> bool:
        return self.pos >= len(self.src)

    def _rch(self) -> str:
        pos, self.pos = self.pos, self.pos + 1
        return self.src[pos]

    def _hex(self, ch: str) -> bool:
        if len(ch) == 1 and ch[0] == '0':
            return self._ch.lower() == 'x'
        elif len(ch) <= 1 or ch[1].lower() != 'x':
            return self._ch.isdigit()
        else:
            return self._ch in string.hexdigits

    def _int(self, ch: str) -> Token:
        while not self._eof and self._hex(ch):
            ch += self._rch()
        else:
            if ch.lower().startswith('0x'):
                return Token.num(int(ch, 16))
            elif ch[0] == '0':
                return Token.num(int(ch, 8))
            else:
                return Token.num(int(ch))

    def _name(self, ch: str) -> Token:
        while not self._eof and (self._ch == '_' or self._ch.isalnum()):
            ch += self._rch()
        else:
            return Token.name(ch)

    def _read(self, ch: str) -> Token:
        if ch.isdigit():
            return self._int(ch)
        elif ch.isidentifier():
            return self._name(ch)
        elif ch in {'*', '<', '>'} and not self._eof and self._ch == ch:
            return Token.punc(self._rch() * 2)
        elif ch in {'+', '-', '*', '/', '%', '&', '|', '^', '~', '(', ')'}:
            return Token.punc(ch)
        else:
            raise SyntaxError('invalid character: ' + repr(ch))

    def _peek(self) -> Token:
        pos = self.pos
        ret = self._next()
        self.pos = pos
        return ret

    def _next(self) -> Token:
        while not self._eof and self._ch.isspace():
            self.pos += 1
        else:
            return Token.end() if self._eof else self._read(self._rch())

    def _grab(self, tk: Token, getvalue: Callable[[str], int]) -> int:
        match tk.tag:
            case TokenKind.Num  : return tk.int_value
            case TokenKind.Name : return getvalue(tk.str_value)
            case _              : raise SyntaxError('integer or identifier expected, got ' + repr(tk))

    __pred__ = [
        {'<<', '>>'},
        {'|'},
        {'^'},
        {'&'},
        {'+', '-'},
        {'*', '/', '%'},
        {'**'},
    ]

    __binary__ = {
        '+'  : lambda a, b: a + b,
        '-'  : lambda a, b: a - b,
        '*'  : lambda a, b: a * b,
        '/'  : lambda a, b: a / b,
        '%'  : lambda a, b: a % b,
        '&'  : lambda a, b: a & b,
        '^'  : lambda a, b: a ^ b,
        '|'  : lambda a, b: a | b,
        '<<' : lambda a, b: a << b,
        '>>' : lambda a, b: a >> b,
        '**' : lambda a, b: a ** b,
    }

    def _eval(self, op: str, v1: int, v2: int) -> int:
        return self.__binary__[op](v1, v2)

    def _nest(self, nest: int, getvalue: Callable[[str], int]) -> int:
        ret = self._expr(0, nest + 1, getvalue)
        ntk = self._next()

        # it must follows with a ')' operator
        if ntk.tag != TokenKind.Punc or ntk.val != ')':
            raise SyntaxError('")" expected, got ' + repr(ntk))
        else:
            return ret

    def _unit(self, tk: Token, nest: int, getvalue: Callable[[str], int]) -> int:
        match tk.tag:
            case TokenKind.Num                   : return tk.int_value
            case TokenKind.Name                  : return getvalue(tk.str_value)
            case TokenKind.Punc if tk.val == '(' : return self._nest(nest, getvalue)
            case TokenKind.Punc if tk.val == '+' : return self._unit(self._next(), nest, getvalue)
            case TokenKind.Punc if tk.val == '-' : return -self._unit(self._next(), nest, getvalue)
            case TokenKind.Punc if tk.val == '~' : return ~self._unit(self._next(), nest, getvalue)
            case _                               : raise SyntaxError('unexpected token ' + repr(tk))

    def _term(self, pred: int, nest: int, getvalue: Callable[[str], int]) -> int:
        lv = self._expr(pred + 1, nest, getvalue)
        tk = self._peek()

        # scan to the end
        while True:
            tt = tk.tag
            tv = tk.val

            # encountered EOF
            if tt == TokenKind.End:
                return lv

            # must be an operator here
            if tt != TokenKind.Punc:
                raise SyntaxError('operator expected, got ' + repr(tk))

            # check for the operator precedence
            if tv not in self.__pred__[pred]:
                return lv

            # apply the operator
            op = self._next()
            rv = self._expr(pred + 1, nest, getvalue)
            lv = self._eval(op.str_value, lv, rv)
            tk = self._peek()

    def _expr(self, pred: int, nest: int, getvalue: Callable[[str], int]) -> int:
        if pred < len(self.__pred__):
            return self._term(pred, nest, getvalue)
        else:
            return self._unit(self._next(), nest, getvalue)

    def eval(self, getvalue: Callable[[str], int]) -> int:
        return self._expr(0, 0, getvalue)
