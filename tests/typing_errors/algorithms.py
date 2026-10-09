"""Each key class takes only its own algorithms, spelt exactly as the JWA names them."""

import ryjwt

ryjwt.SecretKey("secret", algorithms=["RS256"])  # error
ryjwt.SecretKey("secret", algorithms=["hs256"])  # error
ryjwt.PrivateKey("pem", algorithms=["HS256"])  # error
ryjwt.PrivateKey.from_path("path", algorithms=["ES256", "HS256"])  # error
ryjwt.PublicKey("pem", algorithms=["ES521K"])  # error
ryjwt.PublicKey.from_jwks("jwks", algorithms=["HS256"])  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["HS512"])  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["EDDSA"])  # error
ryjwt.SecretKey("secret", algorithms=["HS256"]).encode({}, algorithm="RS256")  # error
ryjwt.PrivateKey("pem", algorithms=["ES256"]).encode({}, algorithm="HS256")  # error
ryjwt.SecretKey("secret", algorithms="HS256")  # error
