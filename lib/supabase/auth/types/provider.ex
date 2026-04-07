defmodule Supabase.Auth.Types.Provider do
  @moduledoc """
  Custom Ecto type for OAuth provider validation.

  Supports both built-in providers and custom providers.
  Built-in providers can be passed as atoms (`:github`) or strings (`"github"`).
  Inputs are normalized to lowercase before validation.
  Custom providers must use the `custom:identifier` format with lowercase identifiers.

  Built-in providers are represented as atoms in Elixir (for backward compatibility).
  Custom providers are represented as strings.
  ## Built-in Providers

  apple, azure, bitbucket, discord, email, facebook, figma, github, gitlab, google,
  kakao, keycloak, linkedin, linkedin_oidc, notion, phone, slack, spotify, twitch,
  twitter, workos, zoom, fly

  ## Custom Providers

  Custom providers use lowercase identifiers in the format `custom:identifier`. For example:
  - `"custom:mycompany"`
  - `"custom:sso-provider"`

  ## Examples

      iex> cast(:github)
      {:ok, :github}

      iex> cast("google")
      {:ok, :google}

      iex> cast("invalid:provider")
      :error
  """

  use Ecto.Type

  @builtins_atoms ~w[apple azure bitbucket discord email facebook figma fly github gitlab google kakao keycloak linkedin linkedin_oidc notion phone slack spotify twitch twitter workos zoom]a
  @builtins Enum.map(@builtins_atoms, &Atom.to_string/1)
  @builtins_string_to_atom Map.new(@builtins_atoms, &{Atom.to_string(&1), &1})
  @custom_provider_regex ~r/^custom:[a-z0-9][a-z0-9_-]*$/
  @max_provider_length 128

  @spec type() :: :string
  def type, do: :string

  @doc """
  Casts the value to a provider.

  Accepts atoms (for built-in providers) and strings (for both built-in and custom).
  String inputs are trimmed and lowercased before validation.
  """
  @spec cast(term()) :: {:ok, atom() | String.t()} | :error
  def cast(value) when is_atom(value) do
    provider = Atom.to_string(value)

    if provider in @builtins do
      {:ok, value}
    else
      :error
    end
  end

  def cast(value) when is_binary(value), do: cast_binary(value)

  def cast(_), do: :error

  @spec dump(term()) :: {:ok, String.t()} | :error
  def dump(value) do
    case cast(value) do
      {:ok, provider} when is_atom(provider) -> {:ok, Atom.to_string(provider)}
      {:ok, provider} when is_binary(provider) -> {:ok, provider}
      :error -> :error
    end
  end

  @spec load(term()) :: {:ok, atom() | String.t()} | :error
  def load(value) when is_binary(value), do: cast_binary(value)

  def load(_), do: :error

  @doc """
  Returns the list of built-in provider names.
  """
  @spec builtins() :: [atom()]
  def builtins, do: @builtins_atoms

  @doc """
  Checks if a provider identifier is valid.

  Built-in providers must be in the known list.
  Custom providers must match lowercase `custom:identifier`.

  Expects a normalized lowercase provider string.
  """
  @spec valid_provider?(term()) :: boolean
  def valid_provider?(provider) when is_binary(provider) do
    byte_size(provider) <= @max_provider_length and
      (provider in @builtins or Regex.match?(@custom_provider_regex, provider))
  end

  def valid_provider?(_), do: false

  @spec cast_binary(String.t()) :: {:ok, atom() | String.t()} | :error
  defp cast_binary(value) do
    normalized = value |> String.trim() |> String.downcase()

    cond do
      normalized in @builtins ->
        {:ok, Map.fetch!(@builtins_string_to_atom, normalized)}

      Regex.match?(@custom_provider_regex, normalized) and byte_size(normalized) <= @max_provider_length ->
        {:ok, normalized}

      true ->
        :error
    end
  end
end
