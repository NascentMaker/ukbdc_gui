import re
from .mnemonics import scancodes, mnemonics
from ctypes import c_uint16, c_uint8

class MacroTag(object):
	def __init__(self):
		pass

	@property
	def code(self):
		return codes[type(self)]

class PressEvent(MacroTag):
	def __init__(self, mnemonic):
		self.mnemonic = mnemonic
		super(PressEvent, self).__init__()

	def __str__(self):
		return "p %s" % self.mnemonic

	def to_binary(self):
		return b"\x00" + bytes(chr(scancodes[self.mnemonic]), "ascii")

class ReleaseEvent(MacroTag):
	def __init__(self, mnemonic):
		self.mnemonic = mnemonic
		super(ReleaseEvent, self).__init__()

	def __str__(self):
		return "r %s" % self.mnemonic

	def to_binary(self):
		return b"\x01" + bytes(chr(scancodes[self.mnemonic]), "ascii")

class ClickEvent(MacroTag):
	def __init__(self, mnemonic):
		self.mnemonic = mnemonic
		super(ClickEvent, self).__init__()

	def __str__(self):
		return "%s" % self.mnemonic

	def to_binary(self):
		return b"\x02" + bytes(chr(scancodes[self.mnemonic]), "ascii")

class SetPostDelay(MacroTag):
	def __init__(self, delay):
		self.delay = delay
		super(SetPostDelay, self).__init__()

	def __str__(self):
		return ".delay %s" % self.delay

	def to_binary(self):
		return b"\x03" + self.delay.to_binary()

class SetClickDelay(MacroTag):
	def __init__(self, delay):
		self.delay = delay
		super(SetClickDelay, self).__init__()

	def __str__(self):
		return ".click_delay %i" % self.delay

	def to_binary(self):
		return b"\x04" + self.delay.to_binary()

class Macro(object):
	def __init__(self):
		pass

codes = {
		PressEvent:	0x00,
		ReleaseEvent:	0x01,
		ClickEvent:	0x02,
		SetPostDelay:	0x03,
		SetClickDelay:	0x04
}

tag_types = {v:k for k, v in codes.items()}

class MacroError(Exception):
	pass

class DelayTime(object):
	CONST = 0
	UNIFORM = 1
	NORMAL = 2

	def __init__(self, dist, arg1, arg2 = None):
		self.dist = dist
		self.arg1, self.arg2 = arg1, arg2

	@staticmethod
	def from_string(txt):
		fst, *args = re.split("[ \t]+", txt)
		try:
			return DelayTime(DelayTime.CONST, int(fst))
		except ValueError:
			try:
				if fst == "uniform":
					return DelayTime(DelayTime.UNIFORM, int(args[0]), int(args[1]))
				elif fst == "normal":
					return DelayTime(DelayTime.NORMAL, int(args[0]), int(args[1]))
				else:
					raise MacroError("unknown distribution type: %s" % fst)
			except IndexError:
				raise MacroError("not enough parameters to distribution %s" % fst)

	def __str__(self):
		if self.dist == self.CONST:
			return str(self.arg1)
		elif self.dist == self.UNIFORM:
			return "uniform %i %i" % (self.arg1, self.arg2)
		elif self.dist == self.NORMAL:
			return "normal %i %i" % (self.arg1, self.arg2)
		else:
			raise MacroError("internal error")

	def to_binary(self):
		return bytes(chr(self.dist), "ascii") + c_uint16(self.arg1) + c_uint16(self.arg2)

	@staticmethod
	def from_binary(blob):
		dist = blob[0]
		arg1 = blob[1] + (blob[2] << 8)
		arg2 = blob[3] + (blob[4] << 8)
		return DelayTime(dist, arg1, arg2)


def text_to_macro(txt):
	lines = filter(lambda e: len(e) != 0, re.split("\r?\n+", txt))
	for line in lines:
		tokens = re.split("[ \t]+", line)
		fst, *args = tokens
		if fst == ".delay":
			yield SetPostDelay(DelayTime.from_string(' '.join(args)))
		elif fst == ".delay_click":
			yield SetClickDelay(DelayTime.from_string(' '.join(args)))
		elif len(args) == 0:
			yield ClickEvent(fst)
		elif fst == "p":
			yield PressEvent(args[0])
		elif fst == "r":
			yield ReleaseEvent(args[0])

def macro_to_text(macro):
	return "\n".join([str(x) for x in macro])

def macro_to_binary(macro):
	return b''.join(map(lambda x: x.to_binary(), macro))

def make_mnemonic(scancode):
	try:
		return mnemonics[scancode]
	except KeyError:
		return "0x%.2x" % scancode

def macro_from_binary(blob):
	pos = 0
	while pos < len(blob):
		tag_type = tag_types[blob[pos]]
		if tag_type in [PressEvent, ReleaseEvent, ClickEvent]:
			yield tag_type(make_mnemonic(blob[pos+1]))
			pos += 2
		elif tag_type in [SetPostDelay, SetClickDelay]:
			yield tag_type(DelayTime.from_binary(blob[pos+1:pos+6]))
			pos += 6
