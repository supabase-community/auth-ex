
## Authentication routes

  <%= if not live? do %>
  scope "/", <%= web_module %> do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get "/register", RegistrationController, :new
    post "/register", RegistrationController, :create
  end
  <% end %>

  scope "/", <%= web_module %> do
    pipe_through [:browser]

    <%= if live? do %>
    live_session :current_user,
      on_mount: [{<%= inspect auth_module %>, :mount_current_user}] do
      live "/login", LoginLive, :new
    end

    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete
    post "/login/:token", SessionController, :token

    <% else %>

    get "/login", SessionController, :new
    post "/login/:token", SessionController, :token
    post "/login", SessionController, :create
    delete "/logout", SessionController, :delete

    <% end %>
  end
