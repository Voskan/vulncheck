defmodule Gateway.MixProject do
  use Mix.Project

  def project, do: [app: :gateway, version: "0.1.0", elixir: "~> 1.18", deps: deps()]

  def application, do: [mod: {Gateway.Application, []}, extra_applications: [:logger]]

  defp deps do
    [
      {:bandit, "1.5.0"},
      {:plug, "1.15.2"},
      {:tesla, "1.8.0"},
      {:mint, "1.5.2"},
      {:hackney, "1.18.1"},
      {:jason, "~> 1.4"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
