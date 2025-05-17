defmodule <%= web_module %>.SettingsLive do
  use <%= web_module %>, :live_view

  def render(assigns) do
    ~H"""
    <.header>
      Account Settings
      <:subtitle>Manage your account settings</:subtitle>
    </.header>

    <div class="space-y-12 divide-y">
      <div>
        <.simple_form for={@email_form} id="email_form" phx-submit="update_email">
          <.input field={@email_form[:email]} type="email" label="Email" required />

          <:actions>
            <.button phx-disable-with="Changing...">Change Email</.button>
          </:actions>
        </.simple_form>
      </div>
      <div>
        <.simple_form for={@password_form} id="password_form" phx-submit="update_password">
          <.input field={@password_form[:password]} type="password" label="New Password" required />
          <.input
            field={@password_form[:password_confirmation]}
            type="password"
            label="Confirm New Password"
            required
          />

          <:actions>
            <.button phx-disable-with="Changing...">Change Password</.button>
          </:actions>
        </.simple_form>
      </div>
    </div>
    """
  end

  def mount(_params, _session, socket) do
    email_form = to_form(%{"email" => socket.assigns.current_user.email}, as: "user")
    password_form = to_form(%{}, as: "user")

    {:ok, assign(socket, email_form: email_form, password_form: password_form)}
  end

  def handle_event("update_email", %{"user" => user_params}, socket) do
    case <%= supabase_client || "{%Supabase.Client{}, #{supabase_url}, #{supabase_key}}" %> |> Supabase.GoTrue.update_user(socket, %{email: user_params["email"]}) do
      {:ok, socket} ->
        {:noreply,
         socket
         |> put_flash(:info, "Email updated successfully")
         |> assign(email_form: to_form(%{"email" => user_params["email"]}, as: "user"))}

      {:error, _} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to update email")
         |> assign(email_form: to_form(%{"email" => user_params["email"]}, as: "user"))}
    end
  end

  def handle_event("update_password", %{"user" => user_params}, socket) do
    case <%= supabase_client || "{%Supabase.Client{}, #{supabase_url}, #{supabase_key}}" %> |> Supabase.GoTrue.update_user(socket, %{password: user_params["password"]}) do
      {:ok, socket} ->
        {:noreply,
         socket
         |> put_flash(:info, "Password updated successfully")
         |> assign(password_form: to_form(%{}, as: "user"))}

      {:error, _} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to update password")
         |> assign(password_form: to_form(%{}, as: "user"))}
    end
  end
end