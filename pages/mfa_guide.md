# Multi-Factor Authentication (MFA) with Supabase GoTrue

This guide covers how to implement Multi-Factor Authentication (MFA) using Supabase's GoTrue authentication service in your Elixir applications.

## Understanding MFA in Supabase

Multi-Factor Authentication provides an additional security layer beyond passwords. Supabase supports several forms of MFA including:

1. **Time-based One-Time Passwords (TOTP)**: Compatible with authenticator apps like Google Authenticator or Authy
2. **SMS-based verification**: One-time codes sent via text message
3. **Email-based verification**: One-time codes sent via email

Each user can have multiple authentication factors associated with their account, represented by the `Supabase.GoTrue.User.Factor` struct.

## MFA Factor Management

### Viewing User Factors

To check if a user has MFA enabled and view their factors:

```elixir
# Get the current user
{:ok, user} = Supabase.GoTrue.get_user(client, session)

# Check for active factors
has_mfa_enabled = Enum.any?(user.factors || [], fn factor -> factor.status == "verified" end)

# Get all factors
factors = user.factors || []
```

Each factor includes information such as:

```elixir
%Supabase.GoTrue.User.Factor{
  id: "f1d74b2c-9bb7-4c74-b9b9-44a48f261a48",
  type: "totp",
  status: "verified",  # or "unverified"
  friendly_name: "Google Authenticator",
  factor_type: "totp",
  created_at: ~N[2023-01-01 00:00:00],
  updated_at: ~N[2023-01-01 00:00:00]
}
```

## Working with Admin APIs

For admin operations on MFA factors, use the `Supabase.GoTrue.Admin` module:

### Enrolling a TOTP Factor (Admin)

```elixir
{:ok, user_with_factors} = Supabase.GoTrue.Admin.enroll_factor(
  client, 
  user_id, 
  %{type: "totp", friendly_name: "My Authenticator App"}
)
```

This returns a user object with a new unverified factor. The response also includes a QR code URL that should be displayed to the user for scanning with their authenticator app.

### Verifying a TOTP Factor (Admin)

After the user scans the QR code, they need to verify their factor by entering a code:

```elixir
{:ok, verified_factor} = Supabase.GoTrue.Admin.verify_factor(
  client,
  user_id,
  factor_id,
  %{challenge: "123456"}  # Code from authenticator app
)
```

### Challenging a Factor (Admin)

When a user attempts to access a protected resource, you can challenge their MFA factor:

```elixir
{:ok, challenge} = Supabase.GoTrue.Admin.challenge_factor(
  client,
  user_id,
  factor_id
)
```

### Unenrolling a Factor (Admin)

To remove an MFA factor:

```elixir
:ok = Supabase.GoTrue.Admin.delete_factor(client, user_id, factor_id)
```

## Authenticator Assurance Levels (AAL)

Supabase uses Authenticator Assurance Levels (AAL) to determine the strength of authentication:

- **AAL0**: No authentication
- **AAL1**: Single-factor authentication (e.g., password only)
- **AAL2**: Multi-factor authentication (password + MFA)

You can check the current AAL:

```elixir
aal = user.app_metadata["aal"]  # "aal1" or "aal2"
```

## Requiring MFA for Sensitive Operations

For sensitive operations like changing passwords or making payments, you can use the reauthentication function:

```elixir
# Request a reauthentication challenge
:ok = Supabase.GoTrue.reauthenticate(client, session)

# User completes verification with OTP
{:ok, verified_session} = Supabase.GoTrue.verify_otp(
  client, 
  %{
    type: "reauthentication",
    token: "123456"
  }
)

# Now perform sensitive operation with the new verified session
```

## MFA Integration with Phoenix

### Enrollment Flow in Phoenix Controllers

```elixir
defmodule MyAppWeb.MFAController do
  use MyAppWeb, :controller
  
  def new(conn, _params) do
    user_id = conn.assigns.current_user.id
    
    # Create a new TOTP factor
    {:ok, user_with_factor} = Supabase.GoTrue.Admin.enroll_factor(
      MyApp.Supabase.Client.get(),
      user_id,
      %{type: "totp", friendly_name: "Authenticator App"}
    )
    
    # Get the most recently created factor (the unverified one)
    [new_factor | _] = Enum.sort_by(user_with_factor.factors, & &1.created_at, :desc)
    
    # Render the enrollment page with QR code URL
    render(conn, "new.html", factor: new_factor, qr_code_url: new_factor.totp.qr_code)
  end
  
  def verify(conn, %{"code" => code, "factor_id" => factor_id}) do
    user_id = conn.assigns.current_user.id
    
    case Supabase.GoTrue.Admin.verify_factor(
      MyApp.Supabase.Client.get(),
      user_id,
      factor_id,
      %{challenge: code}
    ) do
      {:ok, _} ->
        conn
        |> put_flash(:info, "MFA successfully enabled!")
        |> redirect(to: Routes.profile_path(conn, :show))
        
      {:error, _} ->
        conn
        |> put_flash(:error, "Invalid verification code")
        |> redirect(to: Routes.mfa_path(conn, :new))
    end
  end
end
```

### Verification Flow in LiveView

```elixir
defmodule MyAppWeb.MFALive do
  use MyAppWeb, :live_view
  
  def mount(_params, session, socket) do
    user_id = socket.assigns.current_user.id
    
    {:ok, challenge} = Supabase.GoTrue.Admin.challenge_factor(
      MyApp.Supabase.Client.get(),
      user_id,
      socket.assigns.current_user.factors |> hd() |> Map.get(:id)
    )
    
    {:ok, assign(socket, challenge_id: challenge.id, error: nil)}
  end
  
  def handle_event("verify", %{"code" => code}, socket) do
    case Supabase.GoTrue.verify_challenge(
      MyApp.Supabase.Client.get(),
      socket.assigns.challenge_id,
      %{code: code}
    ) do
      {:ok, new_session} ->
        {:noreply, 
          socket
          |> put_flash(:info, "Verification successful!")
          |> push_redirect(to: ~p"/dashboard")}
        
      {:error, _} ->
        {:noreply, assign(socket, error: "Invalid verification code")}
    end
  end
end
```

## Best Practices for MFA

1. **Backup Codes**: Provide users with backup codes in case they lose access to their MFA device.

2. **Recovery Options**: Implement account recovery processes for users who lose all authentication factors.

3. **Gradual Adoption**: Consider making MFA optional initially, then mandatory for specific user groups.

4. **UX Considerations**: Clearly explain MFA benefits to users and make the setup process straightforward.

5. **Security Logging**: Log all MFA-related activities for audit purposes.

## Conclusion

MFA significantly improves the security of your application by requiring multiple forms of verification. Supabase's GoTrue service makes it relatively straightforward to implement MFA in your Elixir applications.

For more detailed information, refer to the module documentation for the `Supabase.GoTrue.User.Factor` module and the `Supabase.GoTrue.Admin` module.