# Passkeys (first-factor WebAuthn) with Supabase Auth

This guide covers passkey authentication with Supabase Auth in Elixir applications: registering a passkey for a signed-in user, signing in with a passkey, and managing passkeys afterwards. For WebAuthn as a *second factor* (MFA), see the [MFA guide](mfa_guide.md), which covers the same ceremony from a different endpoint set.

## What passkeys are

A passkey is a WebAuthn credential bound to a website origin and stored by the browser or platform authenticator (Touch ID, Windows Hello, a hardware key). Users authenticate with a biometric or device unlock instead of a password. Supabase Auth supports passkeys in two distinct roles:

1. **First factor**: a passkey replaces the password entirely. Sign-in returns a full session. This is what `Supabase.Auth.Passkey` covers.
2. **Second factor (MFA)**: a WebAuthn factor hardens an existing session from AAL1 to AAL2. This is the `Supabase.Auth.MFA` WebAuthn path.

## Why the ceremony is not in the SDK

The WebAuthn ceremony (`navigator.credentials.create` and `navigator.credentials.get`) only exists in browsers. An Elixir SDK cannot run it, so the SDK covers the HTTP half and your app covers the ceremony:

- **SDK**: fetch challenge options from the Auth server, and verify the browser's credential against it.
- **Your app**: hand the options to a browser JS hook, run the ceremony, serialize the credential back to Elixir.

The credential and options maps cross the boundary **verbatim**. The SDK does not validate or reshape them, so upstream WebAuthn changes do not require SDK updates.

> Passkeys are an experimental GoTrue feature. Enable them for your project in the Supabase dashboard before using these functions.

## Registration flow (signed-in user)

The full loop, one LiveView round trip per step:

1. `Passkey.start_registration/2` fetches creation options and a `challenge_id`.
2. Your LiveView pushes the `options` map to a JS hook.
3. The hook decodes base64url fields into `Uint8Array`, calls `navigator.credentials.create`, and serializes the response back.
4. Your LiveView calls `Passkey.verify_registration/4` with the credential.

```elixir
defmodule MyApp.PasskeyRegistrationLive do
  use MyAppWeb, :live_view

  alias Supabase.Auth.Passkey

  def mount(_params, _session, socket) do
    {:ok, assign(socket, challenge_id: nil)}
  end

  def handle_event("register_passkey", _params, socket) do
    {:ok, client} = current_client(socket)
    session = current_session(socket)

    {:ok, %{challenge_id: challenge_id, options: options}} =
      Passkey.start_registration(client, session)

    {:noreply,
     socket
     |> assign(challenge_id: challenge_id)
     |> push_event("passkey-registration-options", %{"options" => options})}
  end

  def handle_event("passkey-registered", %{"credential" => credential}, socket) do
    {:ok, client} = current_client(socket)
    session = current_session(socket)

    case Passkey.verify_registration(client, session, socket.assigns.challenge_id, credential) do
      {:ok, passkey} ->
        {:noreply, put_flash(socket, :info, "Passkey #{passkey.friendly_name} registered")}

      {:error, error} ->
        {:noreply, put_flash(socket, :error, "Passkey registration failed")}
    end
  end
end
```

The hook does the ceremony. Binary fields on the wire are base64url strings; the browser API needs `Uint8Array`, so the hook converts them before calling `create`:

```javascript
// assets/js/passkey_hook.js
const b64urlToBytes = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

const bytesToB64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

export const PasskeyHook = {
  mounted() {
    this.handleEvent("passkey-registration-options", async ({ options }) => {
      const publicKey = {
        ...options,
        challenge: b64urlToBytes(options.challenge),
        user: { ...options.user, id: b64urlToBytes(options.user.id) },
        excludeCredentials: (options.excludeCredentials || []).map((c) => ({
          ...c,
          id: b64urlToBytes(c.id),
        })),
      };

      const credential = await navigator.credentials.create({ publicKey });
      const response = credential.toJSON();

      this.pushEvent("passkey-registered", { credential: response });
    });
  },
};
```

`credential.toJSON()` serializes the response per the W3C `PublicKeyCredential.toJSON()` shape (`attestationObject`, `clientDataJSON`, and ids as base64url strings), which is exactly what the verify endpoint expects. Attach the hook in your `app.js` with `hooks: { PasskeyHook }` and use `phx-hook="PasskeyHook"` on the element that triggers registration.

## Sign-in flow (no session required)

Sign-in starts without an authenticated session. The authentication options call goes out with your client's default credentials only:

1. `Passkey.start_authentication/2` fetches request options. If your project has captcha enabled, pass `%{captcha_token: token}`.
2. Push the `options` map to the same hook (a `get` ceremony this time).
3. `Passkey.verify_authentication/3` exchanges the credential for a session.

```elixir
def handle_event("sign_in_with_passkey", _params, socket) do
  {:ok, client} = current_client()

  {:ok, %{challenge_id: challenge_id, options: options}} =
    Passkey.start_authentication(client)

  {:noreply,
   socket
   |> assign(challenge_id: challenge_id)
   |> push_event("passkey-authentication-options", %{"options" => options})}
end

def handle_event("passkey-asserted", %{"credential" => credential}, socket) do
  {:ok, client} = current_client()

  case Passkey.verify_authentication(client, socket.assigns.challenge_id, credential) do
    {:ok, session} ->
      # Persisting the session (cookie, session storage) is your app's policy.
      {:noreply, store_session_and_redirect(socket, session)}

    {:error, _error} ->
      {:noreply, put_flash(socket, :error, "Sign in failed")}
  end
end
```

The hook side for sign-in converts fewer fields (`challenge` and, when present, `allowCredentials[].id`) and calls `get` instead of `create`:

```javascript
this.handleEvent("passkey-authentication-options", async ({ options }) => {
  const publicKey = {
    ...options,
    challenge: b64urlToBytes(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({
      ...c,
      id: b64urlToBytes(c.id),
    })),
  };

  const credential = await navigator.credentials.get({ publicKey });

  this.pushEvent("passkey-asserted", { credential: credential.toJSON() });
});
```

## MFA WebAuthn variant

The same hook serves the MFA WebAuthn factor flow; only the options shape and endpoint set differ:

```elixir
# Enroll a WebAuthn factor for the current session
{:ok, factor} = Supabase.Auth.MFA.enroll(client, session, %{
  factor_type: :webauthn,
  friendly_name: "My YubiKey"
})

# Challenge with relying-party configuration
{:ok, challenge} = Supabase.Auth.MFA.challenge(client, session, factor.id, %{
  webauthn: %{rp_id: "example.com", rp_origins: ["https://example.com"]}
})

# challenge.webauthn.credential_options goes to the hook like any other options map
```

Verification posts the credential response back through `MFA.verify/5` with `%{webauthn: %{type: type, rp_id: rp_id, credential_response: credential}}`. See the MFA guide for the complete factor lifecycle.

## Challenge expiry

Challenges expire server-side (about 5 minutes by default). If verification returns the `webauthn_challenge_expired` error code, restart the flow from `start_registration/2` or `start_authentication/2` rather than retrying the verify: a new challenge means new options, including a fresh challenge bytes value. With Conditional UI (the browser autofill prompt), the prompt can outlive the challenge, so treat "user finally clicks" the same way: if the challenge expired, restart silently.

## Managing passkeys

Users manage their own passkeys with the session-token functions; admins use the service-role functions:

```elixir
# List the current user's passkeys
{:ok, passkeys} = Supabase.Auth.Passkey.list(client, session)

# Rename one
{:ok, _passkey} = Supabase.Auth.Passkey.update(client, session, passkey.id, "Laptop key")

# Remove one
:ok = Supabase.Auth.Passkey.delete(client, session, passkey.id)

# Service role: inspect and remove any user's passkeys
{:ok, passkeys} = Supabase.Auth.Admin.list_passkeys(client, user_id)
:ok = Supabase.Auth.Admin.delete_passkey(client, user_id, passkey_id)
```
