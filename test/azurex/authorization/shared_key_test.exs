defmodule Azurex.Authorization.SharedKeyTest do
  use ExUnit.Case
  doctest Azurex.Authorization.SharedKey

  alias Azurex.Authorization.SharedKey

  describe "sign/2" do
    test "success without params" do
      request = %HTTPoison.Request{
        method: :put,
        url: "https://example.com/sample-path",
        body: "sample body",
        headers: [
          {"x-ms-blob-type", "BlockBlob"}
        ],
        options: [recv_timeout: :infinity]
      }

      assert SharedKey.sign(
               request,
               storage_account_name: "dummystorageaccount",
               storage_account_key:
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
               content_type: "text/plain",
               date: ~U[2021-01-01 00:00:00.000000Z]
             ) == %HTTPoison.Request{
               body: "sample body",
               headers: [
                 {"Authorization",
                  "SharedKey dummystorageaccount:rp6KytL/Db5VaY0hnwHWtFb1icf4ENlUewfkwiuB3hc="},
                 {"x-ms-version", "2023-01-03"},
                 {"x-ms-date", "Fri, 01 Jan 2021 00:00:00 GMT"},
                 {"content-type", "text/plain"},
                 {"x-ms-blob-type", "BlockBlob"}
               ],
               method: :put,
               options: [recv_timeout: :infinity],
               url: "https://example.com/sample-path"
             }
    end

    test "success with params" do
      request = %HTTPoison.Request{
        method: :put,
        url: "https://example.com/sample-path",
        body: "sample body",
        headers: [
          {"x-ms-blob-type", "BlockBlob"}
        ],
        params: [timeout: 1],
        options: [recv_timeout: :infinity]
      }

      assert SharedKey.sign(
               request,
               storage_account_name: "dummystorageaccount",
               storage_account_key:
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
               content_type: "text/plain",
               date: ~U[2021-01-01 00:00:00.000000Z]
             ) == %HTTPoison.Request{
               body: "sample body",
               headers: [
                 {"Authorization",
                  "SharedKey dummystorageaccount:lxajxKTm/KB8ntzj+ZHoPc5zPxDm8STBOwQwMHJg6SA="},
                 {"x-ms-version", "2023-01-03"},
                 {"x-ms-date", "Fri, 01 Jan 2021 00:00:00 GMT"},
                 {"content-type", "text/plain"},
                 {"x-ms-blob-type", "BlockBlob"}
               ],
               method: :put,
               options: [recv_timeout: :infinity],
               params: [timeout: 1],
               url: "https://example.com/sample-path"
             }
    end
  end
end
