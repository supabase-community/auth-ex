defmodule Mix.Tasks.Supabase.Gen.Auth do
  @moduledoc """
  Generates authentication logic backed by Supabase and related views for `Phoenix`.

      $ mix supabase.gen.auth [options]

  ## LiveView vs conventional Controllers & Views

  Authentication views can either be generated to use LiveView by passing
  the `--live` option, or they can use conventional Phoenix
  Controllers & Views by passing `--no-live` (default).

  Using the `--live` option is advised if you plan on using LiveView
  elsewhere in your application. The user experience when navigating between
  LiveViews can be tightly controlled, allowing you to let your users navigate
  to authentication views without necessarily triggering a new HTTP request
  each time (which would result in a full page load).

  ## Strategies

  The `--strategy` (`-s`) option can be used to specify the authentication strategy.
  The default strategy is `password`. Also, multiple strategies can be used in the same application
  with multiple `-s` options.

  The available strategies are:

  * `password` - Email and password authentication.
  * `oauth` - OAuth authentication.
  * `anon` - Anonymous authentication.
  * `id_token` - ID token authentication.
  * `sso` - Single sign-on authentication.
  * `otp` - One-time password authentication.

  For each strategy, a `log_in_with_<strategy>` function will be generated in the `MyAppWeb.Auth` module, where `MyApp` is the name of your application.

  ### Example

      $ mix supabase.gen.auth --strategy password --strategy oauth

  ## Options

  * `--live` - Generate LiveView authentication views.
  * `--no-live` - Generate conventional Phoenix Controllers & Views.
  * `--strategy` - The authentication strategy to use. Defaults to `password`.
  * `--provider` - The authentication provider to use if using strategy `oauth` or `id_token`, required then.

  ## Configuration

  To use this task, you need to have at least `supabase_potion` and `supabase_gotrue` packages installed in your project, and `phoenix_live_view` if you want to use LiveView.

  Also, you need to tell the task which `Supabase` client to be used in the generated functions,
  for that you'll need to define a self-managed `Supabase` client in your `config.exs`. You can follow the [documentation about it](https://hexdocs.pm/supabase_potion/Supabase.Client.html).

      import Config

      config :my_app, MyApp.Supabase,
        base_url: "https://<app-name>.supabase.co",
        api_key: "<supabase-api-key>",
        # any additional optional params
        access_token: "<supabase-access-token>",
        db: [schema: "another"],
        auth: [debug: true] # optional

      # this is the specific task config
      config :supabase, authentication_client: MyApp.Supabase

  ## Generated Files

  * `lib/my_app_web/auth.ex` - The authentication module.
  * `lib/my_app_web/controllers/session_controller.ex` - The session controller, with token handling.

  """

  @shortdoc "Generates authentication logic backed by Supabase."

  use Mix.Task

  import Peri

  @switches [
    live: :boolean,
    strategy: :keep,
    provider: :string
  ]

  @aliases [s: :strategy, p: :provider]

  @doc false
  @impl true
  def run(args) do
    Code.ensure_loaded!(Phoenix)
    Code.ensure_loaded!(Mix.Phoenix)

    if Mix.Project.umbrella?() do
      Mix.raise("mix supabase.gen.auth can only be run inside an application directory")
    end

    {opts, _parsed} = OptionParser.parse!(args, strict: @switches, aliases: @aliases)
    config = validate_options!(opts)

    if generated_with_no_html?() do
      Mix.raise("mix supabase.gen.auth requires phoenix_html")
    end

    app_name = Keyword.fetch!(Mix.Project.config(), :app)
    web_app_name = String.to_atom("#{app_name}_web")

    web_module =
      app_name
      |> to_string()
      |> String.split("_", trim: true)
      |> Enum.map(&Macro.camelize/1)
      |> then(&List.update_at(&1, -1, fn last -> last <> "Web" end))
      |> Module.concat()

    auth_module = Module.concat([web_module, "UserAuth"])

    prompt_for_conflicts(app_name)

    _bindings = [
      strategy: config.strategy,
      provider: config.provider,
      live?: config.live,
      web_module: web_module,
      web_app_name: web_app_name,
      auth_module: auth_module,
      route_prefix: nil
    ]

    # TODO generate files
    # use Mix.Phoenix or make "in house"?
  end

  @strategies ~w(password oauth anon id_token sso otp)
  @oauth_providers ~w(apple azure bitbucket discord facebook figma fly github gitlab google keycloak kakao linkedin notion spotify slack workos twitch twitter zoom)

  def validate_provider(data) when is_list(data) do
    strategies = data[:strategy]

    {:ok,
     {:oneof,
      strategies
      |> Enum.map(&String.to_atom/1)
      |> Enum.map(&validate_provider/1)
      |> Enum.uniq()}}
  end

  def validate_provider(:password), do: nil
  def validate_provider(:anon), do: nil
  def validate_provider(:otp), do: nil
  def validate_provider(:sso), do: nil

  def validate_provider(:id_token) do
    {:required, {:enum, ~w(google apple azure facebook)}}
  end

  def validate_provider(:oauth) do
    {:required, {:enum, @oauth_providers}}
  end

  defschema :config,
    live: {:boolean, {:default, false}},
    strategy: {{:list, {:enum, @strategies}}, {:default, [:password]}},
    provider: {:dependent, &validate_provider/1}

  defp validate_options!(options) do
    options
    |> Enum.group_by(fn {k, _} -> k end)
    |> Enum.map(fn {k, v} ->
      {k,
       Enum.map(v, fn {_, v} -> v end)
       |> then(&if length(&1) == 1, do: hd(&1), else: &1)}
    end)
    |> config!()
  end

  defp generated_with_no_html? do
    Mix.Project.config()
    |> Keyword.get(:deps, [])
    |> Enum.any?(fn
      {:phoenix_html, _} -> true
      {:phoenix_html, _, _} -> true
      _ -> false
    end)
    |> Kernel.not()
  end

  defp prompt_for_conflicts(app_name) do
    files = files_to_be_generated(app_name)
    Mix.Phoenix.prompt_for_conflicts(files)
  end

  defp files_to_be_generated(app_name) do
    web_pre = Mix.Phoenix.web_path(app_name)
    web_test_pre = Mix.Phoenix.web_test_path(app_name)

    default = [
      "auth.ex": [web_pre, "user_auth.ex"],
      "auth_test.exs": [web_test_pre, "user_auth_test.exs"],
    ]

    # TODO merge if live?

    default
  end
end
