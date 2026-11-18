defmodule TeslaMintHackney.MixProject do
  use Mix.Project

  def project, do: [app: :tesla_mint_hackney, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  def application, do: [extra_applications: [:logger]]
  defp deps, do: [{:tesla, "== 1.8.0"}, {:mint, "== 1.5.2"}, {:hackney, "== 1.18.1"}]
end
