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
      {:ok, _session} ->
        conn
        |> put_flash(:info, "User created successfully. Please sign in.")
        |> redirect(to: ~p"/login")

      {:error, %Supabase.Error{metadata: metadata}} ->
        message = get_in(metadata, [:resp_body, "msg"])

        conn
        |> put_flash(:error, "Registration failed: #{message}")
        |> render(:new, changeset: nil)
    end
  end
end
