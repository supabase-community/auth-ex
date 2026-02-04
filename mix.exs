defmodule SupabaseAuth.MixProject do
  use Mix.Project

  @version "0.8.0"
  @source_url "https://github.com/supabase-community/auth-ex"

  def project do
    [
      app: :supabase_auth,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description(),
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer: [plt_local_path: "priv/plts", ignore_warnings: ".dialyzerignore.exs", plt_add_apps: [:mix, :ex_unit]]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp supabase_dep do
    if System.get_env("SUPABASE_LOCAL") == "1" do
      {:supabase_potion, path: "../supabase-ex"}
    else
      {:supabase_potion, "~> 0.7"}
    end
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      supabase_dep(),
      {:peri, "~> 0.3"},
      {:jose, "1.11.10"},
      {:plug, "~> 1.15", optional: true},
      {:phoenix, "~> 1.7", optional: true},
      {:phoenix_live_view, "~> 1.0", optional: true},
      {:mox, "~> 1.0", only: :test},
      {:styler, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    %{
      licenses: ["MIT"],
      contributors: ["zoedsoupe"],
      links: %{
        "GitHub" => @source_url,
        "Docs" => "https://hexdocs.pm/supabase_auth"
      },
      files: ~w[lib mix.exs priv/templates README.md LICENSE CHANGELOG.md]
    }
  end

  defp docs do
    [
      main: "Supabase.Auth",
      extras: [
        "README.md",
        "CHANGELOG.md",
        "pages/auth_guide.md",
        "pages/mfa_guide.md",
        "pages/oauth_guide.md"
      ],
      groups_for_extras: [
        Guides: [
          "pages/auth_guide.md",
          "pages/mfa_guide.md",
          "pages/oauth_guide.md"
        ]
      ],
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end

  defp description do
    """
    Integration with the Auth API from Supabase services.
    Provide authentication with MFA, password and magic link.
    """
  end
end
