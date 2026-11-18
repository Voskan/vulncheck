defmodule PlugCowboyMultipart.MixProject do
  use Mix.Project

  def project, do: [app: :plug_cowboy_multipart, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  def application, do: [extra_applications: [:logger], mod: {PlugCowboyMultipart.Application, []}]
  defp deps, do: [{:plug_cowboy, "== 2.7.0"}, {:plug, "== 1.15.2"}]
end
