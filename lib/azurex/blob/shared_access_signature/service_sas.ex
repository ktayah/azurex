defmodule Azurex.Blob.SharedAccessSignature.ServiceSAS do
  @doc """
  Implements Service based Shared Access Signature urls

  Based on:
  https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
  """
  import Azurex.Blob.SharedAccessSignature.Shared

  def build_token(
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
end
