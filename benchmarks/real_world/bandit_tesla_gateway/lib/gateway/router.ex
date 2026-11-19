defmodule Gateway.Router do
  use Plug.Router

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  get "/fetch" do
    {:ok, resp} = Gateway.Client.fetch(conn.query_string)
    send_resp(conn, 200, inspect(resp.status))
  end

  match _ do
    send_resp(conn, 404, "")
  end
end
