defmodule Supabase.Auth.Request.JSONDecoder do
  @moduledoc """
  A body decoder that transforms empty response to a valid map.
  """

  @behaviour Supabase.Fetcher.BodyDecoder

  alias Supabase.Fetcher.Response

  @impl true
  def decode(%Response{body: body}, _ \\ []) do
    body = if body == "", do: "{}", else: body
    Supabase.decode_json(body)
  end
end
