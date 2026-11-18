defmodule PlugCowboyMultipart.Router do
  use Plug.Builder

  plug(Plug.Parsers, parsers: [:urlencoded, :multipart])
  plug(:dispatch)

  def dispatch(conn, _opts), do: Plug.Conn.send_resp(conn, 200, "ok")
end
