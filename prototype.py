#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum
from typing import NamedTuple

class CallingConvention(NamedTuple):
    scalar_args           : tuple[str, ...]
    scalar_result         : str
    floating_point_args   : tuple[str, ...]
    floating_point_result : str

    @classmethod
    def amd64(cls) -> 'CallingConvention':
        return cls(
            scalar_args           = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'),
            scalar_result         = 'rax',
            floating_point_args   = ('xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'),
            floating_point_result = 'xmm0',
        )

    @classmethod
    def arm64(cls) -> 'CallingConvention':
        return cls(
            scalar_args           = ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'),
            scalar_result         = 'x0',
            floating_point_args   = ('v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'),
            floating_point_result = 'v0',
        )

class Parameter:
    name : str
    size : int
    reg  : str

    def __init__(self, name: str, size: int, reg: str):
        self.reg  = reg
        self.name = name
        self.size = size

    def __repr__(self):
        return '<ARG %s(%d): %s>' % (self.name, self.size, self.reg)

class Prototype:
    args: list[Parameter]
    retv: Parameter | None

    def __init__(self, retv: Parameter | None, args: list[Parameter]):
        self.retv = retv
        self.args = args

    def __repr__(self):
        if self.retv is None:
            return '<PROTO (%s)>' % repr(self.args)
        else:
            return '<PROTO (%r) -> %r>' % (self.args, self.retv)

    @property
    def argspace(self) -> int:
        return sum(
            [v.size for v in self.args],
            (0 if self.retv is None else self.retv.size)
        )

class Prototypes(dict[str, Prototype]):
    @staticmethod
    def _dv(c: str) -> int:
        if c == '(':
            return 1
        elif c == ')':
            return -1
        else:
            return 0

    @staticmethod
    def _tk(s: str, p: str) -> bool:
        return s.startswith(p) and (s == p or s[len(p)].isspace())

    @staticmethod
    def _err(msg: str) -> SyntaxError:
        return SyntaxError(
            msg +
            '\n\nThe parser integrated in this tool is just a text-based parser, ' +
            'so please keep the companion .go file as simple as possible and do not use defined types'
        )

    @staticmethod
    def _align(nb: int) -> int:
        return (((nb - 1) >> 3) + 1) << 3

    @classmethod
    def _retv(cls, ret: str, abi: CallingConvention) -> tuple[str, int, str]:
        name, size, xmm = cls._args(ret)
        return name, size, abi.floating_point_result if xmm else abi.scalar_result

    @classmethod
    def _args(cls, arg: str, sv: str = '') -> tuple[str, int, bool]:
        while True:
            if not arg:
                raise SyntaxError('missing type for parameter: ' + sv)
            elif arg[0] != '_' and not arg[0].isalnum():
                return (sv,) + cls._size(arg.strip())
            elif not sv and arg[0].isdigit():
                raise SyntaxError('invalid character: ' + repr(arg[0]))
            else:
                sv += arg[0]
                arg = arg[1:]

    @classmethod
    def _size(cls, name: str) -> tuple[int, bool]:
        if name[0] == '*':
            return cls._align(8), False
        elif name in ('int8', 'uint8', 'byte', 'bool'):
            return cls._align(1), False
        elif name in ('int16', 'uint16'):
            return cls._align(2), False
        elif name == 'float32':
            return cls._align(4), True
        elif name in ('int32', 'uint32', 'rune'):
            return cls._align(4), False
        elif name == 'float64':
            return cls._align(8), True
        elif name in ('int64', 'uint64', 'uintptr', 'int', 'Pointer', 'unsafe.Pointer'):
            return cls._align(8), False
        else:
            raise cls._err('unrecognized type "%s"' % name)

    @classmethod
    def _func(cls, src: list[str], idx: int, depth: int = 0) -> tuple[str, int]:
        for i in range(idx, len(src)):
            for x in map(cls._dv, src[i]):
                if depth + x >= 0:
                    depth += x
                else:
                    raise cls._err('encountered ")" more than "(" on line %d' % (i + 1))
            else:
                if depth == 0:
                    return ' '.join(src[idx:i + 1]), i + 1
        else:
            raise cls._err('unexpected EOF when parsing function signatures')

    @classmethod
    def parse(cls, abi: CallingConvention, src: str) -> tuple[str, 'Prototypes']:
        idx = 0
        pkg = ''
        ret = {}
        buf = src.splitlines()

        # scan through all the lines
        while idx < len(buf):
            line = buf[idx]
            line = line.strip()

            # skip empty lines
            if not line:
                idx += 1
                continue

            # check for package name
            if cls._tk(line, 'package'):
                idx, pkg = idx + 1, line[7:].strip().split()[0]
                continue

            # only cares about those functions that does not have bodies
            if line[-1] == '{' or not cls._tk(line, 'func'):
                idx += 1
                continue

            # prevent type-aliasing primitive types into other names
            if cls._tk(line, 'type'):
                raise cls._err('please do not declare any type with in the companion .go file')

            # find the next function declaration
            decl, pos = cls._func(buf, idx)
            func, idx = decl[4:].strip(), pos

            # find the beginning '('
            nd = 1
            pos = func.find('(')

            # must have a '('
            if pos == -1:
                raise cls._err('invalid function prototype: ' + decl)

            # extract the name and signature
            args = ''
            name = func[:pos].strip()
            func = func[pos + 1:].strip()

            # skip the method declaration
            if not name:
                continue

            # function names must be identifiers
            if not name.isidentifier():
                raise cls._err('invalid function prototype: ' + decl)

            # function names must start with '_'
            if not name.startswith('_'):
                raise cls._err('invalid function name: ' + name)

            # ... but not entirely made of '_'
            if len(set(name)) == 1:
                raise cls._err('"%s" is not a valid function name' % name)

            # extract the argument list
            while nd and func:
                nch  = func[0]
                func = func[1:]

                # adjust the nesting level
                nd   += cls._dv(nch)
                args += nch

            # check for EOF
            if not nd:
                func = func.strip()
            else:
                raise cls._err('unexpected EOF when parsing function prototype: ' + decl)

            # check for multiple returns
            if ',' in func:
                raise cls._err('can only return a single value (detected by looking for "," within the return list)')

            # check for return signature
            if not func:
                retv = None
            elif func[0] == '(' and func[-1] == ')':
                retv = Parameter(*cls._retv(func[1:-1], abi))
            else:
                raise SyntaxError('badly formatted return argument (please use parenthesis and proper arguments naming): ' + func)

            # extract the argument list
            argv = args[:-1].split(',')
            args, alens, afloat = [], [], []

            # parse every argument
            for v in argv:
                s, nb, fp = cls._args(v.strip())
                args.append(s)
                alens.append(nb)
                afloat.append(fp)

            # check for the result
            regs = []
            idxs = [0, 0]

            # split the integer & floating point registers
            for fp in afloat:
                key = 0 if fp else 1
                tab = abi.floating_point_args if fp else abi.scalar_args

                # check the argument count
                if idxs[key] >= len(tab):
                    raise cls._err("too many arguments, consider pack some into a pointer")

                # add the register
                regs.append(tab[idxs[key]])
                idxs[key] += 1

            # register the prototype
            ret[name[1:]] = Prototype(retv, [
                Parameter(arg, size, reg)
                for arg, size, reg in zip(args, alens, regs)
            ])

        # construct the result
        if not ret:
            return pkg, cls()
        else:
            return pkg, cls(ret)
