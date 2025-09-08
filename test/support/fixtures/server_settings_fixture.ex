defmodule Supabase.Auth.ServerSettingsFixture do
  @moduledoc """
  Server settings fixture for Auth. This module provides functions to generate server settings fixtures.
  """

  alias Supabase.Auth.Schemas.ServerSettings

  def server_settings_fixture(attrs \\ %{}) do
    default = %{
      disable_signup: false,
      mailer_autoconfirm: false,
      phone_autoconfirm: false,
      sms_provider: "twilio",
      saml_enabled: false,
      external: %{
        anonymous_users: true,
        apple: true,
        azure: true,
        bitbucket: true,
        discord: true,
        facebook: true,
        figma: true,
        fly: true,
        github: true,
        gitlab: true,
        google: true,
        keycloak: true,
        kakao: true,
        linkedin: true,
        linkedin_oicd: true,
        notion: true,
        spotify: true,
        slack: true,
        slack_oicd: true,
        workos: true,
        twitch: true,
        twitter: true,
        email: true,
        phone: true,
        zoom: true
      }
    }

    attrs
    |> Map.new()
    |> Enum.into(default)
    |> then(&struct(ServerSettings, &1))
  end

  def server_settings_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()

    attrs
    |> server_settings_fixture()
    |> json.encode!()
  end
end
