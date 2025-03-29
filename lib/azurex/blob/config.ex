defmodule Azurex.Blob.Config do
  @moduledoc """
  Azurex Blob Config
  """

  defp conf, do: Application.get_env(:azurex, __MODULE__, [])

  @doc """
  Azure endpoint url, optional
  Defaults to `https://{name}.blob.core.windows.net` where `name` is the `storage_account_name`
  """
  @spec api_url :: String.t()
  def api_url do
    cond do
      api_url = Keyword.get(conf(), :api_url) -> api_url
      api_url = get_connection_string_value("BlobEndpoint") -> api_url
      true -> "https://#{storage_account_name()}.blob.core.windows.net"
    end
  end

  @doc """
  Azure container name, optional.
  """
  @spec default_container :: String.t() | nil
  def default_container do
    Keyword.get(conf(), :default_container) ||
      raise "Must specify `container` because the default container was not provided."
  end

  @doc """
  Azure storage account name.
  Required if `storage_account_connection_string` not set.
  """
  @spec storage_account_name :: String.t()
  def storage_account_name do
    case Keyword.get(conf(), :storage_account_name) do
      nil -> get_connection_string_value("AccountName")
      storage_account_name -> storage_account_name
    end || raise "Azurex.Blob.Config: Missing storage account name"
  end

  defp try_account_key_env(nil) do
    case Keyword.get(conf(), :storage_account_key) do
      nil -> nil
      key -> {:account_key, Base.decode64!(key)}
    end
  end

  defp try_account_key_conn_string(nil) do
    case get_connection_string_value("AccountKey") do
      nil -> nil
      key -> {:account_key, Base.decode64!(key)}
    end
  end

  defp try_account_key_conn_string(value), do: value

  defp try_service_principal(nil) do
    {_missing_values, values} =
      [:storage_client_id, :storage_client_secret, :storage_tenant_id]
      |> Enum.map(&Keyword.get(conf(), &1))
      |> Enum.split_with(&is_nil/1)

    case values do
      [client_id, client_secret, tenant] ->
        {:service_principal, client_id, client_secret, tenant}

      _ ->
        nil
    end
  end

  defp try_service_principal(value), do: value

  defp try_managed_identity(nil) do
    {missing_values, values} =
      [:storage_client_id, :storage_tenant_id, :storage_identity_token]
      |> Enum.map(&Keyword.get(conf(), &1))
      |> Enum.split_with(&is_nil/1)

    case values do
      [client_id, tenant, identity_token] ->
        {:managed_identity, client_id, tenant, identity_token}

      [] ->
        nil

      _ ->
        raise "Azurex.Blob.Config: Missing values for managed identity #{Enum.join(missing_values, ", ")}"
    end
  end

  defp try_managed_identity(value), do: value

  @doc """
  Azure storage account access key. Base64 encoded, as provided by azure UI.
  Required if `storage_account_connection_string` not set.
  """
  @spec auth_method() ::
          {:service_principal, binary(), binary(), binary()}
          | {:account_key, binary()}
          | {:managed_identity, binary(), binary(), binary()}
  def auth_method do
    nil
    |> try_account_key_env
    |> try_account_key_conn_string
    |> try_service_principal
    |> try_managed_identity ||
      raise """
      Azurex.Blob.Config: Missing credentials settings.
      Either set storage account key with: `storage_account_key` or `storage_account_connection_string`
      Or set service principal with: `storage_client_id`, `storage_client_secret` and `storage_tenant_id`
      Or set managed identity with: `storage_client_id`, `storage_tenant_id`, and `storage_identity_token`
      """
  end

  @doc """
  Azure storage account connection string.
  Required if `storage_account_name` or `storage_account_key` not set.
  """
  @spec storage_account_connection_string :: String.t() | nil
  def storage_account_connection_string,
    do: Keyword.get(conf(), :storage_account_connection_string)

  @spec parse_connection_string(nil | binary) :: map
  @doc """
  Parses a connection string to a key value map.

  ## Examples

      iex> parse_connection_string("Key=value")
      %{"Key" => "value"}

      iex> parse_connection_string("Key=value;")
      %{"Key" => "value"}

      iex> parse_connection_string("Key1=hello;Key2=world")
      %{"Key1" => "hello", "Key2" => "world"}

      iex> parse_connection_string(nil)
      %{}
  """
  def parse_connection_string(nil), do: %{}

  def parse_connection_string(connection_string) do
    connection_string
    |> String.split(";", trim: true)
    |> Enum.map(&String.split(&1, "=", parts: 2))
    |> Map.new(fn [key, value] -> {key, value} end)
  end

  @doc """
  Returns the value in the connection string given the string key.
  """
  @spec get_connection_string_value(String.t()) :: String.t() | nil
  def get_connection_string_value(key) do
    storage_account_connection_string()
    |> parse_connection_string
    |> Map.get(key)
  end

  def get_auth_url do
    Keyword.get(conf(), :auth_url) || "https://login.microsoftonline.com"
  end
end
