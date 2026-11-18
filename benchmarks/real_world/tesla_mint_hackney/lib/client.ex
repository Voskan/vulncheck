defmodule TeslaMintHackney.Client do
  use Tesla

  adapter(Tesla.Adapter.Mint)

  def ping, do: get("/")
end
