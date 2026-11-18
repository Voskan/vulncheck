defmodule Api.MixProject do
  use Mix.Project

  def project, do: [app: :api, version: "0.1.0", deps: [{:core, in_umbrella: true}]]
end
