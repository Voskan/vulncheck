defmodule Gateway.Application do
  use Application

  def start(_type, _args) do
    children = [{Bandit, plug: Gateway.Router, port: 4321}]
    Supervisor.start_link(children, strategy: :one_for_one, name: Gateway.Supervisor)
  end
end
