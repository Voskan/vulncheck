defmodule Gateway.Client do
  use Tesla

  plug(Tesla.Middleware.JSON)

  def fetch(path), do: get("https://example.com/" <> path)
end
