
## Authentication routes
  scope "/", <%= web_module %> do
    pipe_through [:browser, :require_authenticated_user]

    delete "/logout", SessionController, :delete    
  end

  scope "/", <%= web_module %> do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    <%= if live? do %>
    live_session :current_user,
      on_mount: [
        {<%= inspect auth_module %>, :mount_current_user},
        {<%= inspect auth_module %>, :redirect_if_user_is_authenticated}
      ] do
      live "/login", LoginLive, :new
      live "/register", RegistrationLive, :new
    end

    post "/login", SessionController, :create
    post "/login/:token", SessionController, :token
    <% else %>
    get "/login", SessionController, :new
    post "/login/:token", SessionController, :token
    post "/login", SessionController, :create
    get "/register", RegistrationController, :new
    post "/register", RegistrationController, :create
    <% end %>
  end
