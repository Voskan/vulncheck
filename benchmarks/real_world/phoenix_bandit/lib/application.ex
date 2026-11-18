defmodule PhoenixBandit.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [{Bandit, plug: PhoenixBandit.Endpoint, port: 4000}]
    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
