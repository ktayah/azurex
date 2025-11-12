defmodule Azurex.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Azurex.Authorization.BearerCache
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Azurex.Supervisor)
  end
end
