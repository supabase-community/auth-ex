defmodule <%= web_module %>.SettingsController do
  use <%= web_module %>, :controller

  alias <%= web_module %>.UserAuth

  def edit(conn, _params) do
    render(conn, :edit, current_user: conn.assigns.current_user)
  end

  def update(conn, %{"user" => user_params}) do
    case <%= supabase_client || "{%Supabase.Client{}, #{supabase_url}, #{supabase_key}}" %> |> Supabase.GoTrue.update_user(conn, user_params) do
      {:ok, conn} ->
        conn
        |> put_flash(:info, "User updated successfully.")
        |> redirect(to: ~p"/settings")

      {:error, _error} ->
        conn
        |> put_flash(:error, "Failed to update user settings.")
        |> render(:edit)
    end
  end
end