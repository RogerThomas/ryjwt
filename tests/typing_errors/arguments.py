"""`decode`, `encode` and the constructors take only the arguments they declare, of their types."""

from typing import Any

import msgspec
import ryjwt


class Claims(msgspec.Struct):
    sub: str


class DictClaims(dict[str, Any]):
    pass


hmac = ryjwt.HMAC("secret", algorithms=["HS256"])
public_key = ryjwt.PublicKey("pem", algorithms=["ES256"])
jwks_client = ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"])

hmac.decode("token", type=int)  # error
hmac.decode("token", type=dict)  # error
hmac.decode("token", type=dict[str, Any])  # error
hmac.decode("token", type=DictClaims)  # error
jwks_client.decode("token", type=dict)  # error
jwks_client.decode("token", type=dict[str, Any])  # error
jwks_client.decode("token", type=DictClaims)  # error
hmac.decode("token", type=list[int])  # error
hmac.decode("token", type=Claims(sub="sub"))  # error
public_key.decode("token", type=str)  # error
hmac.decode("token", audiences="aud")  # error
jwks_client.decode_nowait("token", audiences="aud")  # error
hmac.decode("token", issuer=1)  # error
hmac.decode("token", leeway="1")  # error
hmac.decode(1)  # error
hmac.encode([1])  # error
hmac.encode({}, headers=[("kid", "kid")])  # error
hmac.encode({}, header={"kid": "kid"})  # error
ryjwt.HMAC("secret", algorithm=["HS256"])  # error
ryjwt.HMAC(1, algorithms=["HS256"])  # error
ryjwt.PrivateKey("pem", algorithms=["ES256"], allow_short_secret=True)  # error
ryjwt.HMAC("secret", algorithms=["HS256"], audience=1)  # error
ryjwt.HMAC("secret", algorithms=["HS256"], audiences="aud")  # error
ryjwt.PrivateKey("pem", algorithms=["ES256"], issuer=[1])  # error
ryjwt.PrivateKey.from_path("private.pem", algorithms=["ES256"], audience=b"aud")  # error
ryjwt.PublicKey("pem", algorithms=["ES256"], audience=1)  # error
ryjwt.PublicKey.from_path("public.pem", algorithms=["ES256"], issuer=1)  # error
ryjwt.PublicKey.from_jwks("{}", algorithms=["ES256"], audience=[1])  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"], audience=1)  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"], issuer=[b"iss"])  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"], cooldown="30")  # error
ryjwt.JWKSClient("https://issuer/jwks", algorithms=["ES256"], http=None)  # error
