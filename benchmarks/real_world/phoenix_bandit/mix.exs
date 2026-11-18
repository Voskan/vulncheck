defmodule PhoenixBandit.MixProject do
  use Mix.Project

  def project, do: [app: :phoenix_bandit, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  def application, do: [extra_applications: [:logger], mod: {PhoenixBandit.Application, []}]
  defp deps, do: [{:bandit, "== 1.5.0"}, {:plug, "== 1.15.2"}, {:jason, "== 1.4.4"}]
end
