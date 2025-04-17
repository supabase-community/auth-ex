defmodule Supabase.GoTrue.AutoRefresh do
  @moduledoc """
  A GenServer to automatically refresh auth tokens before they expire.

  ## Usage

  Add this GenServer to your application's supervision tree:

  ```elixir
  # In your application.ex
  def start(_type, _args) do
    children = [
      # ... other children
      {Supabase.Registry, keys: :unique, name: Supabase.Registry},
      {DynamicSupervisor, strategy: :one_for_one, name: Supabase.AutoRefreshSupervisor}
      # ... rest of your supervision tree
    ]

    opts = [strategy: :one_for_one, name: YourApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
  ```

  Then start the auto-refresh process when you get a new session:

  ```elixir
  {:ok, pid} = DynamicSupervisor.start_child(
    Supabase.AutoRefreshSupervisor,
    {Supabase.GoTrue.AutoRefresh, {client, session}}
  )
  ```

  To stop refreshing when the user logs out:

  ```elixir
  Supabase.GoTrue.AutoRefresh.stop(client)
  ```
  """

  use GenServer

  alias Supabase.Client
  alias Supabase.GoTrue
  alias Supabase.GoTrue.Session

  @auto_refresh_tick_duration 30
  @auto_refresh_tick_threshold 3
  @expiry_margin @auto_refresh_tick_threshold * @auto_refresh_tick_duration

  def start_link({%Client{} = client, %Session{} = session}) do
    GenServer.start_link(__MODULE__, {client, session}, name: via_tuple(client))
  end

  def stop(%Client{} = client) do
    case Registry.lookup(Supabase.Registry, client_key(client)) do
      [{pid, _}] -> GenServer.stop(pid, :normal)
      [] -> :ok
    end
  end

  def init({client, session}) do
    state = %{
      client: client,
      session: session,
      timer_ref: schedule_check()
    }

    {:ok, state}
  end

  def handle_info(:check_refresh, %{client: client, session: session, timer_ref: old_timer} = state) do
    Process.cancel_timer(old_timer)

    case check_refresh(client, session) do
      {:ok, new_session} ->
        {:noreply, %{state | session: new_session, timer_ref: schedule_check()}}

      {:error, _reason} ->
        check_ms = to_timeout(second: @auto_refresh_tick_duration * 2)
        {:noreply, %{state | timer_ref: schedule_check(check_ms)}}
    end
  end

  def handle_info(_, state), do: {:noreply, state}

  def terminate(_reason, %{timer_ref: timer_ref}) do
    Process.cancel_timer(timer_ref)
    :ok
  end

  defp schedule_check(delay \\ @auto_refresh_tick_duration) do
    Process.send_after(self(), :check_refresh, to_timeout(second: delay))
  end

  defp check_refresh(%Client{} = client, %Session{} = session) do
    if needs_refresh?(session) do
      GoTrue.refresh_session(client, session.refresh_token)
    else
      {:ok, session}
    end
  end

  def needs_refresh?(%Session{} = session) do
    now = System.os_time(:second)
    margin_in_seconds = to_timeout(second: @expiry_margin)

    session.expires_at != nil and
      now + margin_in_seconds > session.expires_at
  end

  defp via_tuple(client) do
    {:via, Registry, {Supabase.Registry, client_key(client)}}
  end

  defp client_key(client) do
    "auth_refresh:#{client.base_url}|#{client.auth.url}"
  end
end
