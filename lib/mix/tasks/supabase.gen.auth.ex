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

  > ### Warning {: .warning}
  >
  > This task relies on Phoenix CoreComponents and Phoenix templates for now, of course you can edit the generated files to fit your needs.

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
  * `--client` - The Supabase self managed client to use for authentication.
  * `--supabase-url` - The Supabase URL in case to use one-off client. Check the [configuration](#configuration) section below.
  * `--supabase-key` - The Supabase API key in case to use one-off client. Check the [configuration](#configuration) section below.

  ## Configuration

  To use this task, you need to have at least `supabase_potion` and `supabase_gotrue` packages installed in your project, and `phoenix_live_view` if you want to use LiveView or `phoenix` and `phoenix_plug` if you want to use conventional Controllers & (dead) Views.

  Also, you need to tell the task which `Supabase` client to be used in the generated functions,
  for that you have two available options following the [supabase-ex](https://hexdocs.pm/supabase_potion/readme.html#usage) docs

  ### Self-managed client

  The best way is to define a self-managed `Supabase` client in your `config.exs` and app. You can follow the [documentation about it](https://hexdocs.pm/supabase_potion/Supabase.Client.html).

      # lib/my_app/supabase.ex
      defmodule MyApp.Supabase do
        use Supabase.Client, otp_app: :my_app
      end

      # config/config.exs
      import Config

      config :my_app, MyApp.Supabase,
        base_url: "https://<app-name>.supabase.co",
        api_key: "<supabase-api-key>",
        # any additional optional params
        access_token: "<supabase-access-token>",
        db: [schema: "another"],
        auth: [debug: true] # optional

  Then you can invoke this task passing thr basic options in additional to the `--client` option:

      $ mix supabase.gen.auth -s anon --client MyApp.Supabase

  This is the best option if you are going to use the same client in other parts of your application and also to hold and handle authentication tokens for different scopes via `Supabase.Client.update_access_token/2`.

  ### One-off client

  If you don't want to define a self-managed client, you can pass the `--supabase-url` and `--supabase-key` options to the task:

      $ mix supabase.gen.auth -s anon --supabase-url https://<app-name>.supabase.co --supabase-key <supabase-api-key>

  This option is useful if you are going to use the client only in the authentication logic and don't need to handle tokens for different scopes.

  ## Generated Files

  ### LiveView

  * `lib/my_app_web/router.ex` - The authentication routes, modifies the existing one in-place.
  * `lib/my_app_web/auth.ex` - The authentication module.
  * `lib/my_app_web/live/login_live.ex` - The LiveView for the login page.
  * `lib/my_app_web/controllers/session_controller.ex` - The session controller, with token handling.
  * `test/support/conn_case.exs` - The test helper for the authentication, modifies the existing one in-place.

  > ### Note {: .info}
  >
  > All generated files also comes with test files following the same structure.

  ### dead Views

  * `lib/my_app_web/router.ex` - The authentication routes, modifies the existing one in-place.
  * `lib/my_app_web/auth.ex` - The authentication module.
  * `lib/my_app_web/controllers/session_controller.ex` - The session controller, with token handling.
  * `lib/my_app_web/controllers/session_html.ex` - The session view, with the login form.
  * `lib/my_app_web/controllers/session_html/new.html.heex` - The login form.

  > ### Note {: .info}
  >
  > All generated files also comes with test files following the same structure.
  """

  @shortdoc "Generates authentication logic backed by Supabase."

  use Mix.Task

  alias Mix.Tasks.Phx.Gen.Auth.Injector

  import Peri

  @switches [
    live: :boolean,
    strategy: :keep,
    client: :string,
    supabase_url: :string,
    supabase_key: :string
  ]

  @aliases [s: :strategy, c: :client]

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
    endpoint_module = Module.concat([web_module, "Endpoint"])

    bindings = [
      app_name: app_name,
      strategy: config[:strategy],
      live?: config[:live],
      web_module: web_module,
      web_app_name: web_app_name,
      auth_module: auth_module,
      endpoint_module: endpoint_module,
      supabase_client: config[:client],
      supabase_url: config[:supabase_url],
      supabase_key: config[:supabase_key]
    ]

    prompt_for_conflicts(bindings)

    paths = [".", :supabase_gotrue]

    bindings
    |> copy_new_files(paths)
    |> inject_conn_case_helpers(paths)
    |> inject_routes(paths)
    |> maybe_inject_router_import()
    |> print_shell_instructions()
  end

  @strategies ~w(password oauth anon id_token sso otp)

  defschema :config,
    live: {:boolean, {:default, false}},
    strategy: {{:list, {:enum, @strategies}}, {:default, [:password]}},
    client: {:string, {:transform, &String.to_atom/1}},
    supabase_url: :string,
    supabase_key: :string

  defp validate_options!(options) do
    options
    |> Enum.group_by(fn {k, _} -> k end)
    |> Enum.map(fn {k, v} ->
      {k,
       Enum.map(v, fn {_, v} -> v end)
       |> then(&if length(&1) == 1, do: hd(&1), else: &1)}
    end)
    |> config!()
    |> then(fn opts ->
      client = opts[:client]
      url = opts[:supabase_url]
      key = opts[:supabase_key]

      if is_nil(client) and (is_nil(url) or is_nil(key)) do
        Mix.raise("You must provide a client or both supabase-url and supabase-key")
      end

      if not is_nil(client) and (not is_nil(url) or not is_nil(key)) do
        Mix.raise("You can't provide both client and supabase-url or supabase-key")
      end

      opts
    end)
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

  defp prompt_for_conflicts(opts) do
    files = files_to_be_generated(opts)
    Mix.Phoenix.prompt_for_conflicts(files)
  end

  defp files_to_be_generated(opts) do
    app_name = opts[:app_name]
    web_pre = Mix.Phoenix.web_path(app_name)
    controller_pre = Path.join([web_pre, "controllers"])

    default = [
      "auth.ex": [web_pre, "user_auth.ex"],
      "session_controller.ex": [controller_pre, "session_controller.ex"]
    ]

    files =
      if opts[:live?] do
        live_pre = Path.join([web_pre, "live"])

        default ++
          [
            "login_live.ex": [live_pre, "login_live.ex"]
          ]
      else
        html_pre = Path.join([controller_pre, "session_html"])

        default ++
          [
            "session_html.ex": [controller_pre, "session_html.ex"],
            "new.html.heex": [html_pre, "new.html.heex"]
          ]
      end

    for {source, dest} <- files, do: {:eex, to_string(source), Path.join(dest)}
  end

  defp copy_new_files(bindings, paths) do
    files = files_to_be_generated(bindings)
    Mix.Phoenix.copy_from(paths, "priv/templates/supabase.gen.auth/", bindings, files)
    bindings
  end

  defp inject_conn_case_helpers(binding, paths) do
    test_file = "test/support/conn_case.ex"

    paths
    |> Mix.Phoenix.eval_from("priv/templates/supabase.gen.auth/conn_case.exs", binding)
    |> inject_before_final_end(test_file)

    binding
  end

  defp inject_before_final_end(content_to_inject, file_path) do
    with {:ok, file} <- read_file(file_path),
         {:ok, new_file} <- Injector.inject_before_final_end(file, content_to_inject) do
      print_injecting(file_path)
      File.write!(file_path, new_file)
    else
      :already_injected ->
        :ok

      {:error, {:file_read_error, _}} ->
        print_injecting(file_path)

        print_unable_to_read_file_error(
          file_path,
          """

          Please add the following to the end of your equivalent
          #{Path.relative_to_cwd(file_path)} module:

          #{indent_spaces(content_to_inject, 2)}
          """
        )
    end
  end

  defp read_file(file_path) do
    case File.read(file_path) do
      {:ok, file} -> {:ok, file}
      {:error, reason} -> {:error, {:file_read_error, reason}}
    end
  end

  defp print_injecting(file_path, suffix \\ []) do
    Mix.shell().info([:green, "* injecting ", :reset, Path.relative_to_cwd(file_path), suffix])
  end

  defp print_unable_to_read_file_error(file_path, help_text) do
    Mix.shell().error(
      """

      Unable to read file #{Path.relative_to_cwd(file_path)}.

      #{help_text}
      """
      |> indent_spaces(2)
    )
  end

  defp indent_spaces(string, number_of_spaces)
       when is_binary(string) and is_integer(number_of_spaces) do
    indent = String.duplicate(" ", number_of_spaces)

    string
    |> String.split("\n")
    |> Enum.map_join("\n", &(indent <> &1))
  end

  defp inject_routes(binding, paths) do
    web_prefix = Mix.Phoenix.web_path(binding[:app_name])
    file_path = Path.join(web_prefix, "router.ex")

    paths
    |> Mix.Phoenix.eval_from("priv/templates/supabase.gen.auth/routes.ex", binding)
    |> inject_before_final_end(file_path)

    binding
  end

  defp maybe_inject_router_import(binding) do
    web_prefix = Mix.Phoenix.web_path(binding[:app_name])
    file_path = Path.join(web_prefix, "router.ex")
    auth_module = Keyword.fetch!(binding, :auth_module)
    web_module = Keyword.fetch!(binding, :web_module)
    inject = "import #{inspect(auth_module)}"
    use_line = "use #{inspect(web_module)}, :router"

    help_text = """
    Add your #{inspect(auth_module)} import to #{Path.relative_to_cwd(file_path)}:

        defmodule #{inspect(web_module)}.Router do
          #{use_line}

          # Import authentication plugs
          #{inject}

          ...
        end
    """

    with {:ok, file} <- read_file(file_path),
         {:ok, new_file} <-
           Injector.inject_unless_contains(
             file,
             inject,
             &String.replace(&1, use_line, "#{use_line}\n\n  #{&2}")
           ) do
      print_injecting(file_path, " - imports")
      File.write!(file_path, new_file)
    else
      :already_injected ->
        :ok

      {:error, :unable_to_inject} ->
        Mix.shell().info("""

        #{help_text}
        """)

      {:error, {:file_read_error, _}} ->
        print_injecting(file_path)
        print_unable_to_read_file_error(file_path, help_text)
    end

    binding
  end

  defp print_shell_instructions(binding) do
    Mix.shell().info("""

    Once you are ready, visit "/register"
    to create your account and then access inbucket (http://127.0.0.1:54324 locally) to
    see the account confirmation email.
    """)

    binding
  end
end
