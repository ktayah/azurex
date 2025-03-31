defmodule Azurex.Blob.SharedAccessSignature do
  @moduledoc """
  Implements shared access signatures (SAS) on Blob Storage resources.
  """
  alias Azurex.Blob.SharedAccessSignature.UserDelegationSAS
  alias Azurex.Blob.SharedAccessSignature.ServiceSAS
  alias Azurex.Blob.Config

  @doc """
  Generates a SAS url on a resource in a given container.

  ## Params
  - container: the storage container name
  - resource: the path to the resource (blob, container, directory...)
  - opts: an optional keyword list with following options
    - resource_type: one of :blob / :blob_version / :blob_snapshot / :container / directory
      Defaults to :container
    - permissions: a list of permissions. Defaults to [:read]
    - from: a tuple to defined when the SAS url validity begins. Defaults to `now`.
    - expiry: a tuple to set how long before the SAS url expires. Defaults to `{:second, 3600}`.

  ## Examples
  - `SharedAccessSignature.sas_url("my_container", "/", permissions: [:write], expiry: {:day, 2})`
  - `SharedAccessSignature.sas_url("my_container", "foo/song.mp3", resource_type: :blob)`
  """
  @spec sas_url(String.t(), String.t(), [{atom(), any()}]) :: String.t()
  def sas_url(container, resource, opts \\ []) do
    base_url = Azurex.Blob.Config.api_url()
    resource_type = Keyword.get(opts, :resource_type, :container)
    permissions = Keyword.get(opts, :permissions, [:read])
    from = Keyword.get(opts, :from, DateTime.utc_now())
    expiry = Keyword.get(opts, :expiry, {:second, 3600})
    resource = Path.join(container, resource)

    token =
      case Config.auth_method() do
        {:account_key, account_key} ->
          ServiceSAS.build_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            Azurex.Blob.Config.storage_account_name(),
            account_key
          )

        {:managed_identity, _client_id, _tenant_id, _identity_token} ->
          UserDelegationSAS.build_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            Azurex.Blob.Config.storage_account_name()
          )

        _ ->
          raise "Only account key authentication is supported for SAS"
      end

    "#{Path.join(base_url, resource)}?#{token}"
  end
end
