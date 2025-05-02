defmodule <%= inspect web_module %>.SessionController do
  use <%= inspect web_module %>, :controller

  alias Supabase.GoTrue
  alias Supabase.GoTrue.Session

  <%= if live? do %>
  def create(conn, %{"_action" => "confirmed"} = params) do
    create(conn, params, "User confirmed successfully.")
  end

  def create(conn, params) do
    create(conn, params, "Welcome back!")
  end

  defp create(conn, params, info) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- sign_in_with_strategy(client, params) do
      conn
      |> put_flash(:info, info)
      |> <%= inspect auth_module %>.do_login(session, params)
    else
      _ ->
        conn
        |> put_flash(:error, "Invalid credentials")
        |> redirect(to: ~p"/login")
    end
  end

  def token(conn, %{"token" => token} = params) do
    create(conn, Map.put(params, "token", token))
  end
  <% else %>
  def new(conn, _params) do
    render(conn, :new, form: Phoenix.Component.to_form(%{}, as: "user"))
  end

  def create(conn, params) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- sign_in_with_strategy(client, params) do
      conn
      |> put_flash(:info, "Welcome back!")
      |> <%= inspect auth_module %>.do_login(session, params)
    else
      _ ->
        conn
        |> put_flash(:error, "Invalid credentials")
        |> render(:new, form: Phoenix.Component.to_form(%{}, as: "user"))
    end
  end

  def token(conn, %{"token" => token} = params) do
    create(conn, Map.put(params, "token", token))
  end
  <% end %>

  def delete(conn, _params) do
    conn
    |> put_flash(:info, "Logged out successfully.")
    |> <%= inspect auth_module %>.log_out_user(conn, :global)
  end

  # Helper function to determine the right sign-in strategy based on parameters
  defp sign_in_with_strategy(client, %{"user" => %{"email" => email, "password" => password}}) when is_binary(email) and is_binary(password) do
    <%= if "password" in strategy do %>
    GoTrue.sign_in_with_password(client, %{email: email, password: password})
    <% else %>
    {:error, :strategy_not_enabled}
    <% end %>
  end

  defp sign_in_with_strategy(client, %{"user" => %{"token" => token}}) when is_binary(token) do
    <%= if "otp" in strategy do %>
    GoTrue.sign_in_with_otp(client, %{token: token})
    <% else %>
    {:error, :strategy_not_enabled}
    <% end %>
  end

  defp sign_in_with_strategy(client, %{"user" => %{"provider" => provider}}) when is_binary(provider) do
    <%= if "oauth" in strategy do %>
    GoTrue.sign_in_with_oauth(client, %{provider: provider})
    <% else %>
    {:error, :strategy_not_enabled}
    <% end %>
  end

  defp sign_in_with_strategy(client, %{"user" => %{"id_token" => id_token}}) when is_binary(id_token) do
    <%= if "id_token" in strategy do %>
    GoTrue.sign_in_with_id_token(client, %{id_token: id_token})
    <% else %>
    {:error, :strategy_not_enabled}
    <% end %>
  end

  defp sign_in_with_strategy(client, _params) do
    <%= if "anon" in strategy do %>
    GoTrue.sign_in_anonymously(client, %{})
    <% else %>
    {:error, :strategy_not_enabled}
    <% end %>
  end

  <%= if supabase_client do %>
  defp get_client, do: <%= supabase_client %>.get_client()
  <% else %>
  defp get_client do
    url = <%= inspect supabase_url %>
    key = <%= inspect supabase_key %>
    Supabase.init_client(url, key)
  end
  <% end %>
end