defmodule <%= inspect web_module %>.SessionHTML do
  use <%= inspect web_module %>, :html

  embed_templates "session_html/*"
end