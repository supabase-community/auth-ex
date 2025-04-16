defmodule Supabase.GoTrue.Request do
  @moduledoc false

  alias Supabase.Fetcher.Request

  def base(%Supabase.Client{} = client, path) do
    client
    |> Request.new()
    |> Request.with_auth_url(path)
    |> Request.with_http_client(http_client())
    |> Request.with_headers(%{"accept" => "application/json"})
  end

  defp http_client do
    alias Supabase.Fetcher.Adapter.Finch

    Application.get_env(:supabase_gotrue, :http_client, Finch)
  end
end
