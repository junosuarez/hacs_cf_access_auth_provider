from urllib.parse import urljoin
from jwt import PyJWKClient, PyJWTError, decode as decode_jwt
from collections import namedtuple
from typing import Optional
import aiohttp
import functools
from cachetools import TTLCache

def time_cache(max_age, maxsize=10, typed=False):
    def _decorator(fn):
        @functools.lru_cache(maxsize=maxsize, typed=typed)
        def _new(*args, __time_salt, **kwargs):
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            return _new(*args, **kwargs, __time_salt=int(time.time() / max_age))

        return _wrapped

    return _decorator


CfAccessAuthenticated = namedtuple('CfAccessAuthenticated',
                                   ['expires', 'email', 'issuer'])




class CfAccess:
    """Verified authentication via Cloudflare Access reverse proxy headers
    See https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
    """

    _jwks_sets = TTLCache(maxsize=10, ttl=600)

    @staticmethod
    async def jwks_client(issuer):
        # JWKS is a scheme for sharing JWT keys via well-known url
        # this is where CF Access stores theirs

        jwks_url = urljoin(issuer, '/cdn-cgi/access/certs')


        jwk_set = CfAccess._jwks_sets.get(issuer)
        if not jwk_set:
            # PyJWKClient uses blocking http, so we use aiohttp to prime its cache
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_url) as resp:
                    jwk_set = await resp.json()
                    CfAccess._jwks_sets[issuer] = jwk_set
                    # TODO error handling

        client = PyJWKClient(jwks_url, cache_keys=True)
        client.jwk_set_cache.put(jwk_set)
        return client

    @staticmethod
    async def check(token, issuer, audience) -> tuple[Optional[str], Optional[CfAccessAuthenticated]]:
        """Returns either
           `(True, CFAccessAuthenticated)`
        or `(False, err: str)`
        """

        # fetch the signing key
        client = await CfAccess.jwks_client(issuer)
        key= client.get_signing_key_from_jwt(token)

        try:
            verified = decode_jwt(token, key,
                            algorithms=['RS256'],
                            options={
                                 "verify_signature": True,
                                 "require": ['exp']
                            },
                            audience=audience)
            return None, CfAccessAuthenticated(
                expires = verified['exp'],
                issuer = verified['iss'],
                email = verified['email']
            )
        except PyJWTError as err:
            return type(err).__name__, None
