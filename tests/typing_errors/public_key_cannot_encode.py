"""`PublicKey` only decodes."""

import ryjwt

public_key = ryjwt.PublicKey("pem", algorithms=["ES256"])
public_key.encode({"sub": "sub"})  # error
