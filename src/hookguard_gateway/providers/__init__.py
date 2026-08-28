"""One module per Provider signature shape.

Each module registers its factory with the verifier registry at import time,
which is why they are all imported here: Go did this from ``init()``, and the
equivalent guarantee is that importing this package registers every provider.
Adding a provider is one new file plus one line here.
"""

from . import github, paypal, shopify, stripe

__all__ = ["github", "paypal", "shopify", "stripe"]
