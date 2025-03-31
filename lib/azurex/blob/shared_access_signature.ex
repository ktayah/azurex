defmodule Azurex.Blob.SharedAccessSignature do
  @moduledoc """
  Implements shared access signatures (SAS) on Blob Storage resources.

  Based on:
  https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
  """
  alias Azurex.Blob.Config
  alias Azurex.Authorization.Auth

  import SweetXml

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
          build_service_sas_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            Azurex.Blob.Config.storage_account_name(),
            account_key
          )

        {:managed_identity, _client_id, _tenant_id, _identity_token} ->
          {:ok, user_delegation_key} = get_user_delegation_key(from, expiry)

          build_user_delegation_sas_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            Azurex.Blob.Config.storage_account_name(),
            user_delegation_key
          )

        _ ->
          raise "Only account key authentication is supported for SAS"
      end

    "#{Path.join(base_url, resource)}?#{token}"
  end

  defp get_user_delegation_key(from, expiry) do
    %HTTPoison.Request{
      method: :post,
      url: Config.api_url() <> "/",
      body: create_user_delegation_request_body(from, expiry),
      params: [restype: "service", comp: "userdelegationkey"]
    }
    |> Auth.authorize_request()
    |> HTTPoison.request()
    |> case do
      {:ok, %{body: xml, status_code: 200}} -> {:ok, xml}
    end
  end

  defp create_user_delegation_request_body(from, expiry) do
    """
    <?xml version="1.0" encoding="utf-8"?>
      <KeyInfo>
          <Start>#{st(from)}</Start>
          <Expiry>#{se(from, expiry)}</Expiry>
      </KeyInfo>
    """
  end

  defp build_service_sas_token(
         resource_type,
         resource,
         {from, expiry},
         permissions,
         storage_account_name,
         storage_account_key
       ) do
    URI.encode_query(
      sv: sv(),
      st: st(from),
      se: se(from, expiry),
      sr: sr(resource_type),
      sp: sp(permissions),
      sig:
        signature(
          resource_type,
          resource,
          {from, expiry},
          permissions,
          storage_account_name,
          storage_account_key
        )
    )
  end

  defp signature(
         resource_type,
         resource,
         {from, expiry},
         permissions,
         storage_account_name,
         storage_account_key
       ) do
    signature =
      Enum.join(
        [
          sp(permissions),
          st(from),
          se(from, expiry),
          canonicalized_resource(resource, storage_account_name),
          "",
          "",
          "",
          sv(),
          sr(resource_type),
          "",
          "",
          "",
          "",
          "",
          "",
          ""
        ],
        "\n"
      )

    :crypto.mac(:hmac, :sha256, storage_account_key, signature) |> Base.encode64()
  end

  defp build_user_delegation_sas_token(
         resource_type,
         resource,
         {from, expiry},
         permissions,
         storage_account_name,
         user_delegation_key
       ) do
    URI.encode_query(
      sv: sv(),
      st: st(from),
      se: se(from, expiry),
      sr: sr(resource_type),
      sp: sp(permissions),
      skoid: skoid(user_delegation_key),
      sktid: sktid(user_delegation_key),
      skt: skt(user_delegation_key),
      ske: ske(user_delegation_key),
      sks: sks(user_delegation_key),
      skv: skv(user_delegation_key),
      sig:
        user_delegation_sig(
          resource_type,
          resource,
          {from, expiry},
          permissions,
          storage_account_name,
          user_delegation_key
        )
    )
  end

  defp user_delegation_sig(
         resource_type,
         resource,
         {from, expiry},
         permissions,
         storage_account_name,
         user_delegation_key
       ) do
    signature =
      Enum.join(
        [
          sp(permissions),
          st(from),
          se(from, expiry),
          canonicalized_resource(resource, storage_account_name),
          skoid(user_delegation_key),
          sktid(user_delegation_key),
          skt(user_delegation_key),
          ske(user_delegation_key),
          sks(user_delegation_key),
          skv(user_delegation_key),
          "",
          "",
          "",
          "",
          "",
          sv(),
          sr(resource_type),
          "",
          "",
          "",
          "",
          "",
          "",
          ""
        ],
        "\n"
      )

    key = user_delegation_key |> get_xml_value("Value") |> Base.decode64!()
    :crypto.mac(:hmac, :sha256, key, signature) |> Base.encode64()
  end

  defp sv, do: "2020-12-06"

  defp st(date_time), do: date_time |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  defp se(date_time, {unit, amount}),
    do:
      date_time
      |> DateTime.add(amount, unit)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

  @permissions_order ~w(r a c w d x l t m e o p)
  defp sp(permissions) do
    permissions
    |> Enum.map(fn
      :read -> "r"
      :add -> "a"
      :create -> "c"
      :write -> "w"
      :delete -> "d"
      :delete_version -> "x"
      :permanent_delete -> "y"
      :list -> "l"
      :tags -> "t"
      :find -> "f"
      :move -> "m"
      :execute -> "e"
      :ownership -> "o"
      :permissions -> "p"
      :set_immutability_policy -> "i"
    end)
    |> Enum.sort_by(fn p -> Enum.find_index(@permissions_order, &(&1 == p)) end)
    |> Enum.join("")
  end

  defp sr(:blob), do: "b"
  defp sr(:blob_version), do: "bv"
  defp sr(:blob_snapshot), do: "bs"
  defp sr(:container), do: "c"
  defp sr(:directory), do: "d"

  defp canonicalized_resource(resource, storage_account_name) do
    Path.join(["/blob", storage_account_name, resource])
  end

  # For User Delegation SAS keys
  defp skoid(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedOid")
  defp sktid(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedTid")
  defp skt(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedStart")
  defp ske(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedExpiry")
  defp sks(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedService")
  defp skv(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedVersion")

  defp get_xml_value(xml, key) do
    xml |> xpath(~x"/UserDelegationKey/#{key}/text()") |> to_string()
  end
end
