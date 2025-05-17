defmodule <%= web_module %>.RegistrationHTML do
  use <%= web_module %>, :html

  embed_templates "registration_html/*"

  @doc """
  Renders a registration form.
  """
  attr :changeset, :map, default: nil
  attr :action, :string, required: true

  def user_form(assigns) do
    ~H"""
    <.simple_form :let={f} for={@changeset} action={@action}>
      <.error :if={@changeset && @changeset.action}>
        Oops, something went wrong! Please check the errors below.
      </.error>

      <.input field={f[:email]} type="email" label="Email" required />
      <.input field={f[:password]} type="password" label="Password" required />

      <:actions>
        <.button phx-disable-with="Creating account..." class="w-full">Create an account</.button>
      </:actions>
    </.simple_form>
    """
  end
end