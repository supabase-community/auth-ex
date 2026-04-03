defmodule <%= inspect web_module %>.SessionController do
  use <%= inspect web_module %>, :controller

  <%= if live? do %>
  def create(conn, %{"_action" => "confirmed"} = params) do
    create(conn, params, "User confirmed successfully.")
  end

  def create(conn, params) do
    create(conn, params, "Welcome back!")
  end

  defp create(conn, params, info) do
    with {:ok, conn} <- log_in_with_strategy(conn, params) do
      put_flash(conn, :info, info)
    else
      _ ->
        conn
        |> put_flash(:error, "Invalid credentials")
        |> redirect(to: ~p"/login")
    end
  end
  <% else %>
  def new(conn, _params) do
    render(conn, :new, form: Phoenix.Component.to_form(%{}, as: "user"))
  end

  def create(conn, params) do
    with {:ok, conn} <- log_in_with_strategy(conn, params) do
      put_flash(conn, :info, "Welcome back!")
    else
      _ ->
        conn
        |> put_flash(:error, "Invalid credentials")
        |> render(:new, form: Phoenix.Component.to_form(%{}, as: "user"))
    end
  end
  <% end %>

  def token(conn, %{} = params) do
    create(conn, %{"user" => params})
  end

  def delete(conn, _params) do
    client = conn.assigns.supabase_client

    conn
    |> put_flash(:info, "Logged out successfully.")
    |> <%= inspect auth_module %>.log_out_user(client, :global)
  end

  defp get_client!(conn) do
    conn.assigns[:supabase_client] ||
      raise "Supabase client not found in conn assigns. Make sure to assign :supabase_client in your pipeline."
  end

  <%= if "password" in strategy do %>
  def log_in_with_strategy(conn, %{"user" => %{"email" => email, "password" => password}}) when is_binary(email) and is_binary(password) do
    client = get_client!(conn)
    <%= inspect auth_module %>.log_in_user_with_password(conn, client, %{"email" => email, "password" => password})
  end
  <% end %>

  <%= if "otp" in strategy do %>
  def log_in_with_strategy(conn, %{"user" => %{"token_hash" => token, "type" => type}})
    when is_binary(token) do
    client = get_client!(conn)
    <%= inspect auth_module %>.verify_otp_and_log_in(conn, client, %{token_hash: token, type: type})
  end

  def log_in_with_strategy(conn, %{"user" => %{} = params}) do
    client = get_client!(conn)
    <%= inspect auth_module %>.log_in_user_with_otp(conn, client, params)
  end
  <% end %>

  <%= if "oauth" in strategy do %>
  def log_in_with_strategy(conn, %{"user" => %{"provider" => provider}})
    when is_binary(provider) do
    client = get_client!(conn)
    <%= inspect auth_module %>.log_in_user_with_oauth(conn, client, %{"provider" => provider})
  end
  <% end %>

  <%= if "id_token" in strategy do %>
  def log_in_with_strategy(conn, %{"user" => %{"id_token" => id_token}})
    when is_binary(id_token) do
    client = get_client!(conn)
    <%= inspect auth_module %>.log_in_user_with_id_token(conn, client, %{"id_token" => id_token})
  end
  <% end %>

  <%= if "anon" in strategy do %>
  def log_in_with_strategy(conn, _params) do
    client = get_client!(conn)
    <%= inspect auth_module %>.log_in_user_anonymously(conn, client)
  end
  <% end %>
end
