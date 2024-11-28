# CfAccess Auth Provider for Home Assistant

This custom component allows you to delegate authentication to a [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/) authenticated reverse proxy.

## Prerequisites

1. You have Home Assistant and [HACS](https://hacs.xyz/) installed.
2. You have Cloudflare Access setup - the free tier is ok, but configuring it is beyond the scope of this readme. There's multiple moving pieces here, but it might look like:
   1. Cloudflare Domain
   2. Cloudflare Zero Trust Application Policy
   3. `cloudflared` tunnel to local reverse proxy
   4. Local Home Assistant instance
3. You're comfortable with reverse proxies and other network config.
4. Your Home Assistant users have `username` values that exactly match the email addresses Cloudflare Access is authenticating.
5. It's useful for me, maybe it will be useful for you, but it might not work at all. I'm sorry if it causes frustration. Please consider this very experimental.

## Installation

Add this repository to [HACS](https://hacs.xyz/)

Update your configuration.yaml file with

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 1.2.3.4/32 # This needs to be set to the IP of your reverse proxy
cfaccess:
  issuer: https://<yourteam>.cloudflareaccess.com
  audience: <audience ID token from Application Overview>
  # Optional if you're using something other than cloudflare but which you believe is cfaccess compatible
  # jwt_header: Cf-Access-Jwt-Assertion
  # Optionally enable debug mode to see the headers Home-Assistant gets
  debug: true
# Optionally, if something is not working right, add this block below to get more information
logger:
  default: info
  logs:
    custom_components.cfaccess: debug
```

Afterwards, restart Home Assistant and try accessing it from your Cloudflare Access domain.

## How it works

This was forked from https://github.com/BeryJu/hass-auth-header, so it might conflict if you try installing both AuthProviders at once.

On boot, two main things are done when the integration is enabled:

1. The default `LoginFlowIndexView` view is replaced. This view is called when you submit the login form. The replacement for this view, `RequestLoginFlowResourceView`, simply adds the HTTP Request to the context. This context is passed to authentication Providers.

   Normally the Request is not included, as none of the providers require it.

2. The CfAccess Authentication Provider is injected into the providers, _before_ the other authentication providers.

   This ensures that Header auth is tried first, and if it fails the user can still use username/password.

On an incoming request:

1. Users authenticate themselves to Cloudflare Access (CFA) using various Identity Providers (e.g. Google Auth, OpenID, GitHub, etc. You can self-host your own if you're a masochist). Cloudflare manages the sessions.
2. CFA adds a header to the incoming request saying what the user's email is. It's a signed JWT, so you can verify that it hasn't been tampered with. If you trust the signature, and trust CFA, then you can trust that this is the user's email address.
3. This CfAccessAuthProvider integration transparently verifies the signature, looks for the corresponding Home Assistant user, and transparently signs them in.

Instead of Home Assistant showing a login page, that's now CFA's job.

For now, you still have to manually configure users in Home Assistant, but the general paradigm of "zero trust" network access makes me think I might change that in the future, so that users are created first in CFA and then created on the fly in Home Assistant, like they would be in other applications.

## Help! Everything is broken!

If anything goes wrong or Home Assistant fails to load the component correctly, simply remove the `cfaccess` block from your configuration file and restart HASS.

## Forked from

https://github.com/BeryJu/hass-auth-header

Thank you!
