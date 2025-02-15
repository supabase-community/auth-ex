defmodule Supabase.GoTrue.Schemas.ServerSettings do
  @moduledoc """
  This schema is used to validate and parse the parameters for server settings.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type external_t :: %__MODULE__.External{
          anonymous_users: boolean,
          apple: boolean,
          azure: boolean,
          bitbucket: boolean,
          discord: boolean,
          facebook: boolean,
          figma: boolean,
          fly: boolean,
          github: boolean,
          gitlab: boolean,
          google: boolean,
          keycloak: boolean,
          kakao: boolean,
          linkedin: boolean,
          linkedin_oicd: boolean,
          notion: boolean,
          spotify: boolean,
          slack: boolean,
          slack_oicd: boolean,
          workos: boolean,
          twitch: boolean,
          twitter: boolean,
          email: boolean,
          phone: boolean,
          zoom: boolean
        }

  @type t :: %__MODULE__{
          disable_signup: boolean,
          mailer_autoconfirm: boolean,
          phone_autoconfirm: boolean,
          sms_provider: String.t(),
          saml_enabled: boolean,
          external: external_t
        }

  @derive Jason.Encoder
  @primary_key false
  embedded_schema do
    field(:disable_signup, :boolean)
    field(:mailer_autoconfirm, :boolean)
    field(:phone_autoconfirm, :boolean)
    field(:sms_provider, :string)
    field(:saml_enabled, :boolean)

    embeds_one :external, External, primary_key: false do
      @derive Jason.Encoder
      field(:anonymous_users, :boolean)
      field(:apple, :boolean)
      field(:azure, :boolean)
      field(:bitbucket, :boolean)
      field(:discord, :boolean)
      field(:facebook, :boolean)
      field(:figma, :boolean)
      field(:fly, :boolean)
      field(:github, :boolean)
      field(:gitlab, :boolean)
      field(:google, :boolean)
      field(:keycloak, :boolean)
      field(:kakao, :boolean)
      field(:linkedin, :boolean)
      field(:linkedin_oicd, :boolean)
      field(:notion, :boolean)
      field(:spotify, :boolean)
      field(:slack, :boolean)
      field(:slack_oicd, :boolean)
      field(:workos, :boolean)
      field(:twitch, :boolean)
      field(:twitter, :boolean)
      field(:email, :boolean)
      field(:phone, :boolean)
      field(:zoom, :boolean)
    end
  end

  @fields ~w(disable_signup mailer_autoconfirm phone_autoconfirm sms_provider saml_enabled)a

  def parse(source \\ %__MODULE__{}, %{} = attrs) do
    source
    |> cast(attrs, @fields)
    |> cast_embed(:external, with: &external_changeset/2, required: false)
    |> apply_action(:insert)
  end

  @external_fields ~w(anonymous_users apple azure bitbucket discord facebook figma fly github gitlab google keycloak kakao linkedin linkedin_oicd notion spotify slack slack_oicd workos twitch twitter email phone zoom)a

  defp external_changeset(source, attrs) do
    cast(source, attrs, @external_fields)
  end
end
