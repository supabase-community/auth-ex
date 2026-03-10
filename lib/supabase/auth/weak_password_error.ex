defmodule Supabase.Auth.WeakPasswordError do
  @moduledoc """
  Helpers for working with weak password errors from GoTrue.

  GoTrue returns structured weak password data in error responses:

      %{
        "error_code" => "weak_password",
        "msg" => "Password too short",
        "weak_password" => %{"reasons" => ["length"]}
      }

  The default `Supabase.HTTPErrorParser` preserves this in `metadata.resp_body`,
  but it's not ergonomic to pattern-match on. This module enriches the error's
  metadata with a `weak_password_reasons` key for easy pattern matching:

      {:error, %Supabase.Error{metadata: %{weak_password_reasons: [:length]}}}

  ## Reasons

  - `:length` — password is too short
  - `:characters` — password lacks required character diversity
  - `:pwned` — password was found in a known breach database

  ## Examples

      case Auth.sign_up(client, creds) do
        {:error, %Supabase.Error{metadata: %{weak_password_reasons: reasons}}} ->
          # handle weak password with reasons like [:length, :characters]

        {:error, %Supabase.Error{} = err} ->
          # handle other errors
      end

  Or using the helper functions:

      case Auth.sign_up(client, creds) do
        {:error, err} when is_struct(err, Supabase.Error) ->
          if WeakPasswordError.weak_password?(err) do
            reasons = WeakPasswordError.reasons(err)
            # ...
          end
      end
  """

  @type reason :: :length | :characters | :pwned

  @known_reasons ~w[length characters pwned]

  @doc """
  Enriches a `Supabase.Error` with weak password data if present in the response body.

  Parses `metadata.resp_body` for weak password information and adds
  `weak_password_reasons` to the metadata map. Returns the error unchanged
  if it's not a weak password error.
  """
  @spec maybe_enrich(Supabase.Error.t()) :: Supabase.Error.t()
  def maybe_enrich(%Supabase.Error{metadata: %{resp_body: resp_body}} = error) when is_map(resp_body) do
    cond do
      match?(%{"weak_password" => %{"reasons" => [_ | _]}}, resp_body) ->
        enrich(error, resp_body)

      resp_body["error_code"] == "weak_password" ->
        enrich(error, resp_body)

      true ->
        error
    end
  end

  def maybe_enrich(%Supabase.Error{} = error), do: error

  @doc """
  Returns `true` if the error contains weak password reasons in its metadata.
  """
  @spec weak_password?(Supabase.Error.t()) :: boolean()
  def weak_password?(%Supabase.Error{metadata: %{weak_password_reasons: [_ | _]}}), do: true
  def weak_password?(%Supabase.Error{}), do: false

  @doc """
  Extracts the weak password reasons from an enriched error.

  Returns an empty list if the error is not a weak password error.
  """
  @spec reasons(Supabase.Error.t()) :: [reason()]
  def reasons(%Supabase.Error{metadata: %{weak_password_reasons: reasons}}), do: reasons
  def reasons(%Supabase.Error{}), do: []

  defp enrich(%Supabase.Error{} = error, resp_body) do
    reasons =
      resp_body
      |> get_in(["weak_password", "reasons"])
      |> List.wrap()
      |> Enum.filter(&(&1 in @known_reasons))
      |> Enum.map(&String.to_existing_atom/1)

    message = resp_body["msg"] || resp_body["message"] || error.message

    metadata = Map.put(error.metadata, :weak_password_reasons, reasons)
    %{error | message: message, metadata: metadata}
  end
end
