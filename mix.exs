defmodule SupabaseAuth.MixProject do
  use Mix.Project

  @version "0.3.10"
  @source_url "https://github.com/zoedsoupe/gotrue-ex"

  def project do
    [
      app: :supabase_gotrue,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description()
    ]
  end

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
