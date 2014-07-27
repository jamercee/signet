r"""tests initialization"""

import sys, os
PARENT = os.path.dirname(os.path.dirname(__file__))
if sys.path[0] != PARENT:
    sys.path.insert(0, PARENT)

