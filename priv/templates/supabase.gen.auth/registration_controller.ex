defmodule <%= web_module %>.RegistrationController do
  use <%= web_module %>, :controller

  alias <%= web_module %>.UserAuth

  def new(conn, _params) do
    render(conn, :new, changeset: nil)
  end

  def create(conn, %{"user" => user_params}) do
    {:ok, client} = UserAuth.get_client()
    %{"email" => email, "password" => password} = user_params

    case Supabase.GoTrue.sign_up(client, %{email: email, password: password}) do
      {:ok, _user} ->
        conn
        |> put_flash(:info, "User created successfully. Please sign in.")
        |> redirect(to: ~p"/login")

      {:error, error} ->
        conn
        |> put_flash(:error, "Registration failed: #{error.message}")
        |> render(:new, changeset: nil)
    end
  end
end
