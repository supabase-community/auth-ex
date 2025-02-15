defmodule Supabase.GoTrue.ServerSettingsFixture do
  @moduledoc """
  Server settings fixture for GoTrue. This module provides functions to generate server settings fixtures.
  """

  alias Supabase.GoTrue.Schemas.ServerSettings

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

    Enum.into(Map.new(attrs), default)
    |> then(&struct(ServerSettings, &1))
  end

  def server_settings_fixture_json(attrs \\ %{}) do
    server_settings_fixture(attrs)
    |> Jason.encode!()
  end
end
