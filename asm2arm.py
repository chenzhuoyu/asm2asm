#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct

from keystone import Ks
from keystone import KS_ARCH_ARM64
from keystone import KS_MODE_LITTLE_ENDIAN

from parsing import Line
from parsing import Command
from parsing import Expression

from prototype import Prototypes
from prototype import CallingConvention

from subroutine import Subroutine
from subroutine import save_subr_refs
from subroutine import make_subr_filename

STUB_NAME   = '__native_entry__'
ENTRY_SIZE  = 12

class Label(str):
    @property
    def name(self) -> str:
        return self + ''

    def __str__(self) -> str:
        return self + ':'

class Reference:
    op   : str
    name : str

    def __init__(self, name: str, op: str):
        self.op   = op
        self.name = name

    def __str__(self) -> str:
        if not self.op:
            return self.name
        else:
            return f'{self.name}@{self.op}'

    __registers__ = {
        *(f'w{i}' for i in range(31)),
        *(f'x{i}' for i in range(31)),
        'wzr', 'xzr',
        'sp', 'lr',
    }

    @classmethod
    def checked_parse(cls, val: str, refs: set[str]) -> 'str | Reference':
        reg = val.lower()
        tab = cls.__registers__

        # check for registers
        if reg in tab:
            return reg

        # parse the operator
        vals = val.rsplit('@', 1)
        name = vals[0]

        # check for valid reference
        if name not in refs:
            return val
        elif len(vals) == 1:
            return cls(name, '')
        else:
            return cls(name, vals[1])

class Instruction:
    mnemonic: str
    operands: list[str | Reference]

    def __init__(self, mnemonic: str, operands: list[str | Reference]):
        self.mnemonic = mnemonic
        self.operands = operands

    def __str__(self) -> str:
        if not self.operands:
            return self.mnemonic
        else:
            return '%-8s %s' % (self.mnemonic, ', '.join(map(str, self.operands)))

    @classmethod
    def _basic(cls, val: str) -> tuple[str, str]:
        try:
            p = val.index(',')
        except ValueError:
            return val.rstrip(), ''
        else:
            return val[:p].rstrip(), val[p:]

    @classmethod
    def _memory(cls, val: str) -> tuple[str, str]:
        try:
            p = val.find(',', val.index(']'))
        except ValueError:
            raise SyntaxError('invalid memory operand') from None
        else:
            if p < 0:
                return val.rstrip(), ''
            else:
                return val[:p].rstrip(), val[p:]

    @classmethod
    def _regrefs(cls, val: str, refs: set[str]) -> tuple[str | Reference, str]:
        vv, ret = cls._basic(val)
        return Reference.checked_parse(vv, refs), ret

    @classmethod
    def _operand(cls, val: str, refs: set[str]) -> tuple[str | Reference, str]:
        if val[0] == '#':
            return cls._basic(val)
        elif val[0] == '[':
            return cls._memory(val)
        else:
            return cls._regrefs(val, refs)

    @classmethod
    def parse(cls, ins: str, refs: set[str]) -> 'Instruction':
        val = ins.split(None, 1)
        ret = cls(val[0], [])

        # no operands
        if len(val) == 1:
            return ret

        # get the arguments
        args = val[1]
        args = args.lstrip()

        # parse the arguments
        while True:
            op, args = cls._operand(args, refs)
            ret.operands.append(op)

            # skip the comma and spaces if any
            if not args:
                return ret
            elif args[0] != ',':
                raise SyntaxError('"," expected')
            else:
                args = args[1:].lstrip()

class Translator:
    ks     : Ks
    out    : list[str]
    mbuf   : bytes
    subr   : dict[str, Subroutine]
    align  : int
    labels : dict[str, int]

    def __init__(self):
        self.ks     = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.out    = []
        self.mbuf   = b''
        self.subr   = {}
        self.align  = 0
        self.labels = {}

    def _drain(self):
        if self.mbuf:
            val, = struct.unpack('I', self.mbuf.ljust(4, b'\x00'))
            self.out.append('    WORD $0x%08x  // %s' % (val, repr(self.mbuf)[1:]))

    def _flush(self):
        for n in range(2, 0, -1):
            while len(self.mbuf) >= n * 4:
                buf, self.mbuf = self.mbuf[:n * 4], self.mbuf[n * 4:]
                self.out.append('    %s  // %s' % ('; '.join(['WORD $0x%08x'] * n) % struct.unpack('%dI' % n, buf), repr(buf)[1:]))

    def _lookup(self, key: str) -> int:
        if key not in self.labels:
            raise SyntaxError('unresolved reference to %s' % repr(key))
        else:
            return self.labels[key]

    def _assemble(self, ins: str, pc: int) -> int:
        ret, n = self.ks.asm(ins, addr = pc, as_bytes = True)
        assert n == 1 and isinstance(ret, bytes)
        return int.from_bytes(ret, 'little')

    def _size_byte(self, *_) -> int: return 1
    def _size_word(self, *_) -> int: return 2
    def _size_long(self, *_) -> int: return 4
    def _size_quad(self, *_) -> int: return 8

    def _size_ascii(self, _: int, cmd: Command) -> int:
        if len(cmd.args) != 1:
            raise SyntaxError('invalid .ascii command')
        else:
            return len(cmd.args[0])

    def _size_space(self, _: int, cmd: Command) -> int:
        if len(cmd.args) != 1:
            raise SyntaxError('invalid .space command')
        else:
            return cmd.as_int(0)

    def _size_p2align(self, pc: int, cmd: Command) -> int:
        if len(cmd.args) != 1:
            raise SyntaxError('invalid .p2align command')
        else:
            align = 1 << cmd.as_int(0)
            self.align = max(self.align, align)
            return ((align - 1) - (pc & (align - 1)) + 1) & (align - 1)

    def _emit_raw(self, v: bytes) -> int:
        self.mbuf += v
        self._flush()
        return len(v)

    def _emit_byte(self, _: int, cmd: Command) -> int:
        self.out.append('// ' + str(cmd))
        return self._emit_raw(struct.pack('B', Expression(cmd.as_str(0)).eval(self._lookup)))

    def _emit_word(self, _: int, cmd: Command) -> int:
        self.out.append('// ' + str(cmd))
        return self._emit_raw(struct.pack('H', Expression(cmd.as_str(0)).eval(self._lookup)))

    def _emit_long(self, _: int, cmd: Command) -> int:
        self.out.append('// ' + str(cmd))
        return self._emit_raw(struct.pack('I', Expression(cmd.as_str(0)).eval(self._lookup)))

    def _emit_quad(self, _: int, cmd: Command) -> int:
        self.out.append('// ' + str(cmd))
        return self._emit_raw(struct.pack('Q', Expression(cmd.as_str(0)).eval(self._lookup)))

    def _emit_ascii(self, _: int, cmd: Command) -> int:
        if len(cmd.args) != 1:
            raise SyntaxError('invalid .ascii command')
        else:
            return self._emit_raw(cmd.as_bytes(0))

    def _emit_space(self, _: int, cmd: Command) -> int:
        if len(cmd.args) != 1:
            raise SyntaxError('invalid .space command')
        else:
            self.out.append('// ' + str(cmd))
            return self._emit_raw(b'\x00' * cmd.as_int(0))

    def _emit_p2align(self, pc: int, cmd: Command) -> int:
        curr = self.align
        argc = len(cmd.args)

        # must have exactly 1 argument
        if argc != 1:
            raise SyntaxError('invalid .p2align command')

        # calculate alignment size
        align = 1 << cmd.as_int(0)
        count = ((align - 1) - (pc & (align - 1)) + 1) & (align - 1)

        # update the alignment
        if align > curr:
            self.align = align

        # generate the instruction
        self.out.append('// %s (%d bytes)' % (cmd, count))
        return self._emit_raw(b'\x00' * count)

    __command_tab__ = {
        '.byte'     : (_size_byte    , _emit_byte    ),
        '.word'     : (_size_word    , _emit_word    ),
        '.long'     : (_size_long    , _emit_long    ),
        '.quad'     : (_size_quad    , _emit_quad    ),
        '.ascii'    : (_size_ascii   , _emit_ascii   ),
        '.space'    : (_size_space   , _emit_space   ),
        '.p2align'  : (_size_p2align , _emit_p2align ),
    }

    def _emit_ref(self, _: int, ref: Label):
        if not self.mbuf:
            self.out.append(str(ref))
        else:
            self.out.append('// . = %s - %d' % (ref.name, len(self.mbuf)))

    def _emit_cmd(self, pc: int, cmd: Command, *, dry_run: bool) -> int:
        if cmd.cmd not in self.__command_tab__:
            return pc
        elif dry_run:
            return pc + self.__command_tab__[cmd.cmd][0](self, pc, cmd)
        else:
            return pc + self.__command_tab__[cmd.cmd][1](self, pc, cmd)

    def _emit_instr(self, pc: int, ins: Instruction) -> int:
        npc = pc + 4
        src = str(ins)

        # must have no pending bytes
        if self.mbuf:
            raise RuntimeError('unflushed bytes: ' + repr(self.mbuf))

        # resolve references
        for i, op in enumerate(ins.operands):
            if isinstance(op, Reference):
                if op.op == 'PAGE':
                    ins.operands[i] = '#0x%08x' % (self.labels[op.name] & ~0xfff)
                elif op.op == 'PAGEOFF':
                    ins.operands[i] = '#0x%08x' % (self.labels[op.name] & 0xfff)
                else:
                    ins.operands[i] = '#0x%08x' % self.labels[op.name]

        # assemble the instruction
        self.out.append('\tWORD $0x%08x  // %s' % (self._assemble(str(ins), pc), src))
        return npc

    def _check_align(self, pc: int) -> int:
        if pc & 3 or self.mbuf:
            raise SyntaxError('unaligned PC')
        else:
            return pc

    def translate(self, src: str, proto: Prototypes, *, name: str = '__native_entry__'):
        ins = []
        refs = set()
        lines = list(filter(None, map(Line.remove_comments, src.splitlines())))

        # scan for labels
        for line in lines:
            if line[-1] == ':':
                refs.add(line[:-1])

        # parse the lines
        for line in lines:
            if line[-1] == ':':
                ins.append(Label(line[:-1]))
            elif line[0] == '.':
                ins.append(Command.parse(line))
            else:
                ins.append(Instruction.parse(line, refs))

        # initial PC values
        pc = ENTRY_SIZE
        nb = ENTRY_SIZE

        # calculate the location of each label
        for v in ins:
            if isinstance(v, Label):
                self.labels[v] = nb
            elif isinstance(v, Command):
                nb = self._emit_cmd(nb, v, dry_run = True)
            elif isinstance(v, Instruction):
                nb = self._check_align(nb + 4)
            else:
                raise SystemError('unreachable')

        # insert the entry point
        self.out.append('TEXT ·%s(SB), NOSPLIT, $0' % name)
        self.out.append('    NO_LOCAL_POINTERS')

        # insert alignment adjustment code if needed
        if self.align:
            if self.align < 4:
                raise ValueError('invalid alignment value')
            else:
                self.out.append(f'    PCALIGN ${self.align}')

        # insert code for retrieving the entry point
        self.out.append('    ADR     0(PC), R0')
        self.out.append('    MOVD    R0, ret<>+8(SP)')
        self.out.append('    RET')
        self.out.append('')

        # convert each instructions
        for v in ins:
            if isinstance(v, Label):
                self._emit_ref(pc, v)
            elif isinstance(v, Command):
                pc = self._emit_cmd(pc, v, dry_run = False)
            elif isinstance(v, Instruction):
                pc = self._emit_instr(self._check_align(pc), v)
            else:
                raise SystemError('unreachable')

        # check for remaining bytes
        if self.mbuf:
            self._flush()
            self._drain()

        # generate the subroutines
        for name, item in sorted(proto.items()):
            self.subr[name] = Subroutine(
                offset     = self.labels[name],
                stack_size = 0,
            )

def main():
    src = []
    asm = Translator()

    # check for arguments
    if len(sys.argv) < 3:
        print('* usage: %s <output-file> <clang-asm> ...' % sys.argv[0], file = sys.stderr)
        sys.exit(1)

    # parse the prototype
    try:
        with open(os.path.splitext(sys.argv[1])[0] + '.go', 'r', newline = None) as fp:
            pkg, proto = Prototypes.parse(CallingConvention.arm64(), fp.read())
    except SyntaxError as e:
        print('SyntaxError:', e, file = sys.stderr)
        sys.exit(1)

    # read all the sources, and combine them together
    for fn in sys.argv[2:]:
        with open(fn, 'r', newline = None) as fp:
            src.extend(fp.read().splitlines())

    # convert the original sources
    asm.out.append('// +build !noasm !appengine')
    asm.out.append('// Code generated by asm2asm, DO NOT EDIT.')
    asm.out.append('')
    asm.out.append('#include "go_asm.h"')
    asm.out.append('#include "funcdata.h"')
    asm.out.append('#include "textflag.h"')
    asm.out.append('')
    asm.translate('\n'.join(src), proto, name = STUB_NAME)

    # save the converted result
    with open(sys.argv[1], 'w') as fp:
        for line in asm.out:
            print(line, file = fp)

    # save the subroutine stubs
    save_subr_refs(
        pkg  = pkg,
        subr = asm.subr,
        base = STUB_NAME,
        name = os.path.join(os.path.dirname(sys.argv[1]), make_subr_filename(sys.argv[1])),
    )

if __name__ == '__main__':
    main()
