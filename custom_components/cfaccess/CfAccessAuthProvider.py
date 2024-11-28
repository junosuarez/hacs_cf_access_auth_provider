"""CfAccess Authentication provider.

Get authenticated user from CfAccess signed JWT in header from reverse proxy

This is a shallow integration - from the CfAccess JWT, we start a new HASS user session and save the tokens in the browser.
"""
import logging
from typing import Any, Dict, List, Optional, cast

from aiohttp.web import Request
from homeassistant.auth.models import Credentials, User, UserMeta
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider, LoginFlow
from homeassistant.auth.providers.trusted_networks import (
    InvalidAuthError,
    InvalidUserError,
    IPAddress,
)
from homeassistant.core import callback

from . import CfAccess

CONF_HEADER = "jwt_header"
CONF_AUDIENCE = "audience"
CONF_ISSUER = "issuer"

_LOGGER = logging.getLogger(__name__)

@AUTH_PROVIDERS.register("cfaccess")
class CfAccessAuthProvider(AuthProvider):
    """CfAccess Authentication Provider.

    Allow access to users based on a signed JWT header set by CF Access reverse-proxy.
    """

    DEFAULT_TITLE = "CfAccess Authentication"

    @property
    def type(self) -> str:
        return "cfaccess"

    @property
    def support_mfa(self) -> bool:
        """CfAccess Authentication Provider does not support HASS MFA."""
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        assert context is not None
        request = cast(Request, context.get("request"))

        header_name = self.config[CONF_HEADER] or CfAccess.CfAccessHeaderName
        if header_name not in request.headers:
            _LOGGER.info("Request header " + header_name + " missing, returning empty flow")
            return HeaderLoginFlow(
                self,
                None,
                [],
                cast(IPAddress, context.get("conn_ip_address"))
            )

        err, authenticated = await CfAccess.CfAccess.check(
            token=request.headers[header_name],
            issuer = self.config[CONF_ISSUER],
            audience = self.config[CONF_AUDIENCE]
        )

        if err:
            _LOGGER.info("CfAccess Error: " + err)
            return HeaderLoginFlow(
                self,
                None,
                [],
                cast(IPAddress, context.get("conn_ip_address"))
            )

        # for now, the HASS users _must_ have login usernames (not diplay names) that exactly match the CfAccess email
        # TODO: optional config mapping emails to usernames

        remote_user = authenticated.email

        # Translate username to id
        users = await self.store.async_get_users()
        available_users = [
            user for user in users if not user.system_generated and user.is_active
        ]
        return HeaderLoginFlow(
            self,
            remote_user,
            available_users,
            cast(IPAddress, context.get("conn_ip_address"))
        )

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Trusted network auth provider should never create new user.
        TODO: yeah it should, this should be managed on the CfAccess side, not HASS
        """
        raise NotImplementedError

    async def async_get_or_create_credentials(
        self, flow_result: Dict[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        user_id = flow_result["user"]

        users = await self.store.async_get_users()
        for user in users:
            if not user.system_generated and user.is_active and user.id == user_id:
                for credential in await self.async_credentials():
                    if credential.data["user_id"] == user_id:
                        return credential
                cred = self.async_create_credentials({"user_id": user_id})
                await self.store.async_link_user(user, cred)
                return cred

        # We only allow login as existing HASS user
        raise InvalidUserError

    @callback
    def async_validate_access(self, ip_addr: IPAddress) -> None:
        """Make sure the access is from trusted_proxies.

        Raise InvalidAuthError if not.
        Raise InvalidAuthError if trusted_proxies is not configured.
        """
        if not self.hass.http.trusted_proxies:
            _LOGGER.warning("trusted_proxies is not configured")
            raise InvalidAuthError("trusted_proxies is not configured")

        if not any(
            ip_addr in trusted_network
            for trusted_network in self.hass.http.trusted_proxies
        ):
            _LOGGER.warning("Remote IP not in trusted proxies: %s", ip_addr)
            raise InvalidAuthError("Not in trusted_proxies")


class HeaderLoginFlow(LoginFlow):
    """Handler for the login flow."""

    def __init__(
        self,
        auth_provider: CfAccessAuthProvider,
        remote_user: str,
        available_users: List[User],
        ip_address: IPAddress
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._available_users = available_users
        self._remote_user = remote_user
        self._ip_address = ip_address

    async def async_step_init(self, user_input=None) -> Dict[str, Any]:
        """Handle the step of the form."""

        try:
            _LOGGER.debug("Validating access for IP: %s", self._ip_address)
            cast(CfAccessAuthProvider, self._auth_provider).async_validate_access(
                self._ip_address
            )
        except InvalidAuthError as exc:
            _LOGGER.debug("Invalid auth: %s", exc)
            return self.async_abort(reason="not_allowed")

        for user in self._available_users:
            _LOGGER.debug("Checking user: %s", user.name)
            for cred in user.credentials:
                if "username" in cred.data:
                    _LOGGER.debug("Found username in credentials: %s", cred.data["username"])
                    if cred.data["username"] == self._remote_user:
                        _LOGGER.debug("Username match found, finishing login flow")
                        return await self.async_finish({"user": user.id})
            if user.name == self._remote_user:
                _LOGGER.debug("User name match found, finishing login flow")
                return await self.async_finish({"user": user.id})

        _LOGGER.debug("No matching user found")
        return self.async_abort(reason="not_allowed")
