defmodule Azurex.Blob.SharedAccessSignature.Shared do
  @doc """
  Shared logic and helper functions between different SAS url creation methods
  """
  def sv, do: "2020-12-06"

  def st(date_time), do: date_time |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  def se(date_time, {unit, amount}),
    do:
      date_time
      |> DateTime.add(amount, unit)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

  @permissions_order ~w(r a c w d x l t m e o p)
  def sp(permissions) do
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

  def sr(:blob), do: "b"
  def sr(:blob_version), do: "bv"
  def sr(:blob_snapshot), do: "bs"
  def sr(:container), do: "c"
  def sr(:directory), do: "d"

  def canonicalized_resource(resource, storage_account_name) do
    Path.join(["/blob", storage_account_name, resource])
  end
end
