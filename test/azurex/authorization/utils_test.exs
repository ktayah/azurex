defmodule Azurex.Authorization.UtilsTest do
  use ExUnit.Case

  alias Azurex.Authorization.Utils

  describe("authentication request") do
    test "can format date_time as expected for x-ms-date header" do
      # We do this for backwards compatibility with Elixir 1.9
      {:ok, naive_date_time} = NaiveDateTime.new(2021, 1, 1, 12, 0, 0)
      {:ok, date_time} = DateTime.from_naive(naive_date_time, "Etc/UTC")

      assert Utils.format_date(date_time) == "Fri, 01 Jan 2021 12:00:00 GMT"
    end
  end
end
