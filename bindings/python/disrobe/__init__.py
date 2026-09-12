"""disrobe -- deobfuscator + decompiler suite (Python bindings).

Re-exports every function from the native `disrobe.disrobe` extension
module. See ``help(disrobe)`` for the full surface or visit
https://github.com/1-3-7/disrobe for documentation.
"""

from .disrobe import *  # noqa: F401,F403
from .disrobe import DisrobeError, __doc__, __version__  # noqa: F401
