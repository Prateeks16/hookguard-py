"""The Gateway: terminates inbound webhook traffic, verifies the Provider
signature, and forwards only authenticated requests upstream.

Importing this package registers every provider. In Go that happened for free
-- each provider file's ``init()`` ran as soon as the package was linked -- and
without the import below the equivalent Python failure is a very confusing
``unknown provider 'stripe'`` from a registry nobody populated.
"""

from . import providers as providers
