defmodule TeslaMintHackney.Client do
  use Tesla

  adapter(Tesla.Adapter.Mint)

  def fetch(url), do: get(url)
end
