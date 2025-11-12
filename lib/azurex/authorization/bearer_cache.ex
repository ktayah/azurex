defmodule Azurex.Authorization.BearerCache do
  use GenServer

  @ets_table_name :bearer_token_cache

  def start_link(_args) do
    GenServer.start_link(__MODULE__, nil)
  end

  @impl true
  def init(_) do
    :ets.new(@ets_table_name, [:named_table, :public])

    {:ok, nil}
  end

  def lookup(key) do
    :ets.lookup(@ets_table_name, key)
  end

  def insert(entry) do
    :ets.insert(@ets_table_name, entry)
  end
end
