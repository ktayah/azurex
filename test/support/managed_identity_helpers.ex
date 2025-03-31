defmodule Azurex.ManagedIdentityHelpers do
  @doc """
  Creates a token file in a tmp directory and returns the path
  """
  def create_token_file do
    federated_token_file_path = Path.join([System.tmp_dir(), "temp_file"])
    :ok = File.touch!(federated_token_file_path)
    :ok = File.write!(federated_token_file_path, "identity_token")

    federated_token_file_path
  end
end
