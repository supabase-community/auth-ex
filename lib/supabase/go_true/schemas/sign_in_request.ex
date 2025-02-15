defmodule Supabase.GoTrue.Schemas.SignInRequest do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in a user.

  ## Fields

  Fields depends on the sign in method, so check their modules to
  see the available fields.
  - Sign in with ID Token: `Supabase.GoTrue.Schemas.SignInWithIdToken`
  - Sign in with OTP: `Supabase.GoTrue.Schemas.SignInWithOTP`
  - Sign in with Password: `Supabase.GoTrue.Schemas.SignInWithPassword`
  - Sign in with SSO: `Supabase.GoTrue.Schemas.SignInWithSSO`
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Supabase.GoTrue.Validations

  alias Supabase.GoTrue.Schemas.SignInWithIdToken
  alias Supabase.GoTrue.Schemas.SignInWithOTP
  alias Supabase.GoTrue.Schemas.SignInWithPassword
  alias Supabase.GoTrue.Schemas.SignInWithSSO

  @primary_key false
  embedded_schema do
    field(:email, :string)
    field(:phone, :string)
    field(:password, :string)
    field(:provider, :string)
    field(:access_token, :string)
    field(:nonce, :string)
    field(:id_token, :string)
    field(:provider_id, :string)
    field(:domain, :string)
    field(:create_user, :boolean)
    field(:redirect_to, :string)
    field(:channel, :string)
    field(:data, :map, default: %{})
    field(:code_challenge, :string)
    field(:code_challenge_method, :string)

    embeds_one :gotrue_meta_security, GoTrueMetaSecurity, primary_key: false do
      @derive Jason.Encoder
      field(:captcha_token, :string)
    end
  end

  def create(%SignInWithOTP{} = signin, code_challenge, code_method) do
    attrs = SignInWithOTP.to_sign_in_params(signin, code_challenge, code_method)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :data, :create_user, :redirect_to, :channel])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  def create(%SignInWithSSO{} = signin, code_challenge, code_method) do
    attrs = SignInWithSSO.to_sign_in_params(signin, code_challenge, code_method)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider_id, :domain])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:provider_id, :domain])
    |> apply_action(:insert)
  end

  def create(%SignInWithOTP{} = signin) do
    attrs = SignInWithOTP.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :data, :create_user, :redirect_to, :channel])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  def create(%SignInWithSSO{} = signin) do
    attrs = SignInWithSSO.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider_id, :domain])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:provider_id, :domain])
    |> apply_action(:insert)
  end

  def create(%SignInWithIdToken{} = signin) do
    attrs = SignInWithIdToken.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider, :id_token, :access_token, :nonce])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required([:provider, :id_token])
    |> apply_action(:insert)
  end

  def create(%SignInWithPassword{} = signin) do
    attrs = SignInWithPassword.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.GoTrueMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :password])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required([:password])
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  defimpl Jason.Encoder, for: __MODULE__ do
    alias Supabase.GoTrue.Schemas.SignInRequest

    def encode(%SignInRequest{} = request, opts) do
      request
      |> Map.from_struct()
      |> Map.filter(fn {_k, v} -> not is_nil(v) end)
      |> Map.delete(:redirect_to)
      |> Jason.Encode.map(opts)
    end
  end
end
