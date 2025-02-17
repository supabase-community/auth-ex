defmodule SupabaseAuth.MixProject do
  use Mix.Project

  @version "0.4.0"
  @source_url "https://github.com/supabase-community/auth-ex"

  def project do
    [
      app: :supabase_gotrue,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description(),
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer: [plt_local_path: "priv/plts", ignore_warnings: ".dialyzerignore"]
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

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:supabase_potion, "~> 0.6"},
      {:plug, "~> 1.15", optional: true},
      {:phoenix_live_view, "~> 1.0", optional: true},
      {:mox, "~> 1.0", only: :test},
      {:peri, "~> 0.4.0-rc1"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
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
        "Docs" => "https://hexdocs.pm/supabase_gotrue"
      },
      files: ~w[lib mix.exs README.md LICENSE]
    }
  end

  defp docs do
    [
      main: "Supabase.GoTrue",
      extras: ["README.md"]
    ]
  end

  defp description do
    """
    Integration with the GoTrue API from Supabase services.
    Provide authentication with MFA, password and magic link.
    """
  end
end
