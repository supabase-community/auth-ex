defmodule Supabase.Auth.Request do
  @moduledoc false

  alias Supabase.Fetcher.Request

  def base(%Supabase.Client{} = client, path, opts \\ []) do
    opts = Keyword.merge([decode_body?: true, parse_http_error?: true], opts)

    client
    |> Request.new(opts)
    |> Request.with_auth_url(path)
    |> Request.with_http_client(http_client())
    |> Request.with_headers(%{"accept" => "application/json"})
    |> Request.with_body_decoder(__MODULE__.JSONDecoder)
  end

  defp http_client do
    alias Supabase.Fetcher.Adapter.Finch

    Application.get_env(:supabase_auth, :http_client, Finch)
  end
end
