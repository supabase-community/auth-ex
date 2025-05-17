# Used by "mix format"
[
  inputs: ["*.{ex,exs}", "{config,lib,test}/**/*.{ex,exs}", "priv/templates/**/*.{ex,exs,heex}"],
  import_deps: [:peri, :phoenix],
  plugins: [Styler, Phoenix.LiveView.HTMLFormatter]
]
