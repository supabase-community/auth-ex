defmodule Supabase.GoTrue.Request.JSONDecoder do
  @moduledoc """
  A body decoder that transforms empty response to a valid map.
  """

  alias Supabase.Fetcher.Response

  @behaviour Supabase.Fetcher.BodyDecoder

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
