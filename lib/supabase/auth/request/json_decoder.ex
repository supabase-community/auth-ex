defmodule Supabase.Auth.Request.JSONDecoder do
  @moduledoc """
  A body decoder that transforms empty response to a valid map.
  """

  @behaviour Supabase.Fetcher.BodyDecoder

  alias Supabase.Fetcher.Response

  @impl true
  def decode(%Response{body: body}, opts \\ []) do
    body =
      case body do
        "" -> "{}"
        _ -> body
      end

    keys = Keyword.get(opts, :keys, :strings)
    Jason.decode(body, keys: keys)
  end
end
