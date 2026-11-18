defmodule PhoenixBandit.Endpoint do
  use Plug.Builder

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:dispatch)

  def dispatch(conn, _opts), do: Plug.Conn.send_resp(conn, 200, "ok")
end
