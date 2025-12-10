defmodule Supabase.Auth.Schemas.SignInRequest do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset
  import Supabase.Auth.Validations

  alias Supabase.Auth.Schemas.SignInAnonymously
  alias Supabase.Auth.Schemas.SignInWithIdToken
  alias Supabase.Auth.Schemas.SignInWithOTP
  alias Supabase.Auth.Schemas.SignInWithPassword
  alias Supabase.Auth.Schemas.SignInWithSSO

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

    embeds_one :gotrue_meta_security, AuthMetaSecurity, primary_key: false do
      @moduledoc false
      @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
      field(:captcha_token, :string)
    end
  end

  def create(%SignInWithOTP{} = signin, code_challenge, code_method) do
    attrs = SignInWithOTP.to_sign_in_params(signin, code_challenge, code_method)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :data, :create_user, :redirect_to, :channel])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  def create(%SignInWithSSO{} = signin, code_challenge, code_method) do
    attrs = SignInWithSSO.to_sign_in_params(signin, code_challenge, code_method)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider_id, :domain])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:provider_id, :domain])
    |> apply_action(:insert)
  end

  def create(%SignInWithOTP{} = signin) do
    attrs = SignInWithOTP.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :data, :create_user, :redirect_to, :channel])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  def create(%SignInWithSSO{} = signin) do
    attrs = SignInWithSSO.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider_id, :domain])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required_inclusion([:provider_id, :domain])
    |> apply_action(:insert)
  end

  def create(%SignInWithIdToken{} = signin) do
    attrs = SignInWithIdToken.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:provider, :id_token, :access_token, :nonce])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required([:provider, :id_token])
    |> apply_action(:insert)
  end

  def create(%SignInWithPassword{} = signin) do
    attrs = SignInWithPassword.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.options.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:email, :phone, :password])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> validate_required([:password])
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:insert)
  end

  def create(%SignInAnonymously{} = signin) do
    attrs = SignInAnonymously.to_sign_in_params(signin)
    gotrue_meta = %__MODULE__.AuthMetaSecurity{captcha_token: signin.captcha_token}

    %__MODULE__{}
    |> cast(attrs, [:data])
    |> put_embed(:gotrue_meta_security, gotrue_meta, required: true)
    |> apply_action(:insert)
  end

  @encoder Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)

  defimpl @encoder, for: __MODULE__ do
    alias Supabase.Auth.Schemas.SignInRequest

    def encode(%SignInRequest{} = request, _) do
      request
      |> Map.from_struct()
      |> Map.filter(fn {_k, v} -> not is_nil(v) end)
      |> Map.delete(:redirect_to)
      |> Supabase.encode_json()
    end
  end
end
