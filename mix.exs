defmodule VulnCheck.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/Voskan/vulncheck"

  def project do
    [
      app: :vulncheck,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      escript: escript(),
      package: package(),
      docs: docs(),
      description: description(),
      name: "VulnCheck",
      source_url: @source_url,
      homepage_url: @source_url,
      test_coverage: [summary: [threshold: 85], ignore_modules: [~r/^VulnCheck\.Test\./]],
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit, :inets, :ssl, :public_key, :crypto, :tools],
        flags: [:error_handling, :unknown]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :inets, :ssl, :public_key, :crypto, :tools]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp escript do
    [
      main_module: VulnCheck.CLI,
      name: "vulncheck",
      emu_args: "-noinput"
    ]
  end

  defp description do
    "Function-level reachability vulnerability scanner for Elixir, Erlang, and Gleam " <>
      "that combines OSV.dev and EEF CNA advisories with post-macro .beam call graphs."
  end

  defp package do
    [
      name: "vulncheck",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md docs),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      maintainers: ["Voskan Voskanyan"]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "docs/ARCHITECTURE.md",
        "docs/REACHABILITY_MODEL.md",
        "docs/CONFIGURATION_AND_CI.md",
        "docs/OUTPUT_FORMATS.md"
      ],
      groups_for_modules: [
        "Public API": [VulnCheck, VulnCheck.CLI, VulnCheck.Config],
        Types: ~r/^VulnCheck\.Types\./,
        Workspace: ~r/^VulnCheck\.Workspace/,
        Feeds: ~r/^VulnCheck\.(Feeds|HTTP|Cache)/,
        Analysis: ~r/^VulnCheck\.(Beam|Entrypoints|Solver|Scanner|Semver)/,
        Reporting: ~r/^VulnCheck\.Report/
      ]
    ]
  end
end
