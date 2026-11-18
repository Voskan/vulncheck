defmodule Core.MixProject do
  use Mix.Project

  def project, do: [app: :core, version: "0.1.0", deps: [{:plug, "== 1.15.2"}]]
end
