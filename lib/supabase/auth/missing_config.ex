defmodule Supabase.Auth.MissingConfig do
  @moduledoc false
  defexception [:message]

  def ensure_opts!(opts, module) do
    missing = filter_missing_opts(opts)

    if not Enum.empty?(missing) do
      raise __MODULE__, options: opts, module: module
    end
  end

  @impl true
  def exception(key: :client, module: module) do
    desc = get_missing_desc(:client, module)

    message = """
    The `:client` option need to be a module that implements the `Supabase.Client.Behaviour` behaviour.

    #{desc}
    """

    %__MODULE__{message: message}
  end

  def exception(key: :auth_module) do
    message = """
    You must set up the `:auth_module` option in your config.exs file. This should be the module that contains your authentication handler.
    The authentication handler module should be a module that uses `Supabase.Auth.Plug` or `Supabase.Auth.LiveView` as described into the documentation.
    https://hexdocs.pm/supabase_auth/readme.html#usage
    """

    %__MODULE__{message: message}
  end

  def exception(options: opts, module: module) do
    missing = filter_missing_opts(opts)
    warnings = Enum.map(missing, &get_missing_desc(&1, module))
    message = Enum.join(warnings, "\n\n")
    %__MODULE__{message: message}
  end

  @required_options [:client, :signed_in_path, :not_authenticated_path]

  defp filter_missing_opts(opts) when is_list(opts) do
    missing_keys = @required_options -- Keyword.keys(opts)

    # missing values
    opts
    |> Enum.filter(fn {_, v} -> is_nil(v) end)
    |> Enum.map(fn {k, _} -> k end)
    |> Enum.concat(missing_keys)
    |> then(fn missing ->
      if Code.ensure_loaded?(Phoenix) and is_nil(opts[:endpoint]) do
        [:endpoint | missing]
      else
        missing
      end
    end)
    |> Enum.uniq()
  end

  defp get_missing_desc(:endpoint, module) do
    """
    You must pass the `:endpoint` option to #{inspect(module)} with your Phoenix app's endpoint.
    """
  end

  defp get_missing_desc(:client, module) do
    """
    You must pass the `:client` option to #{inspect(module)} with your Supabase Potion client. Check the Supabase Potion docs for more info: https://hexdocs.pm/supabase_potion/readme.html#usage
    """
  end

  defp get_missing_desc(:signed_in_path, module) do
    """
    You must pass the `:signed_in_path` option to #{inspect(module)} with the path to redirect to after a user signs in.
    """
  end

  defp get_missing_desc(:not_authenticated_path, module) do
    """
    You must pass the `:not_authenticated_path` option to #{inspect(module)} with the path to redirect to when a user is not authenticated.
    """
  end
end
