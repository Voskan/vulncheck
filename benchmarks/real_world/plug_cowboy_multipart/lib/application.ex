defmodule PlugCowboyMultipart.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Plug.Cowboy, scheme: :http, plug: PlugCowboyMultipart.Router, options: [port: 4001]}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
