defmodule Core do
  def parse(qs), do: Plug.Conn.Query.decode(qs)
end
