# Opt-in real-world validation harness (requires network + mix, and rebar3 for the Erlang fixture).
#
#     mix escript.build
#     mix run benchmarks/validate_real_world.exs
#     mix run benchmarks/validate_real_world.exs --offline --bundle feeds.tar.gz --markdown
#
Code.require_file("validation_comparator.exs", __DIR__)

defmodule VulnCheck.Bench.RealWorld do
  alias VulnCheck.Bench.ValidationComparator

  def main(argv) do
    {opts, _args, _invalid} =
      OptionParser.parse(argv,
        strict: [
          keep: :boolean,
          markdown: :boolean,
          offline: :boolean,
          bundle: :string,
          escript: :string
        ]
      )

    escript = Keyword.get(opts, :escript, Path.expand("../vulncheck", __DIR__))

    unless File.regular?(escript) do
      Mix.raise("escript not found at #{escript}; run `mix escript.build` first")
    end

    {expected, _} = Code.eval_file(Path.expand("real_world_expected.exs", __DIR__))

    root =
      Path.join(
        System.tmp_dir!(),
        "vulncheck-realworld-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)

    try do
      projects = generate_projects!(root)

      results =
        for {name, dir, lock_file, build_cmd} <- projects do
          IO.puts(:stderr, "building #{name} in #{dir} ...")
          {build_out, build_code} = run_build(dir, build_cmd)

          if build_code != 0 do
            IO.puts(:stderr, "build failed for #{name}:\n#{build_out}")
          end

          lock_hash = sha256_file(Path.join(dir, lock_file))
          report = scan!(escript, dir, opts)

          result =
            ValidationComparator.compare(name, report, expected.verdicts, expected.packages)

          Map.merge(result, %{
            lock_sha256: lock_hash,
            feed: report["feed"],
            tool: report["tool"]
          })
        end

      summary = ValidationComparator.summarize(results)

      if Keyword.get(opts, :markdown, false) do
        IO.puts(ValidationComparator.to_markdown(summary))
      else
        Enum.each(results, fn r ->
          IO.puts(
            "#{r.project}: matched=#{r.matched}/#{r.total_expected} " <>
              "precision=#{r.precision_percent}% recall=#{r.recall_percent}% " <>
              "noise_reduction=#{r.noise_reduction_percent}% lock_sha256=#{r.lock_sha256}"
          )
        end)
      end

      unless summary.passed? do
        System.halt(1)
      end
    after
      unless Keyword.get(opts, :keep, false), do: File.rm_rf!(root)
    end
  end

  defp scan!(escript, dir, opts) do
    args =
      ["--project-dir", dir, "--format", "json", "--quiet"] ++
        if(Keyword.get(opts, :offline, false), do: ["--offline"], else: []) ++
        if(bundle = Keyword.get(opts, :bundle), do: ["--bundle", bundle], else: [])

    {out, _code} = System.cmd(escript, args)
    JSON.decode!(out)
  end

  defp run_build(dir, {cmd, args, env}) do
    System.cmd(cmd, args, cd: dir, env: env, stderr_to_stdout: true)
  end

  defp sha256_file(path) do
    if File.regular?(path) do
      :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
    else
      "missing"
    end
  end

  defp generate_projects!(root) do
    [
      phoenix_bandit(Path.join(root, "phoenix_bandit")),
      plug_cowboy_multipart(Path.join(root, "plug_cowboy_multipart")),
      tesla_mint_hackney(Path.join(root, "tesla_mint_hackney")),
      umbrella_three_apps(Path.join(root, "umbrella_three_apps")),
      rebar3_hackney(Path.join(root, "rebar3_hackney"))
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp phoenix_bandit(dir) do
    File.mkdir_p!(Path.join(dir, "lib"))

    File.write!(Path.join(dir, "mix.exs"), """
    defmodule PhoenixBandit.MixProject do
      use Mix.Project
      def project, do: [app: :phoenix_bandit, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
      def application, do: [extra_applications: [:logger]]
      defp deps, do: [{:bandit, "== 1.5.0"}, {:plug, "== 1.15.2"}, {:jason, "== 1.4.4"}]
    end
    """)

    File.write!(Path.join(dir, "lib/endpoint.ex"), """
    defmodule PhoenixBandit.Endpoint do
      use Plug.Builder
      plug Plug.Parsers, parsers: [:json], json_decoder: Jason
      plug :dispatch
      def dispatch(conn, _opts), do: Plug.Conn.send_resp(conn, 200, "ok")
    end
    """)

    {"phoenix_bandit", dir, "mix.lock",
     {"sh", ["-c", "mix deps.get && MIX_ENV=prod mix compile"], []}}
  end

  defp plug_cowboy_multipart(dir) do
    File.mkdir_p!(Path.join(dir, "lib"))

    File.write!(Path.join(dir, "mix.exs"), """
    defmodule PlugCowboyMultipart.MixProject do
      use Mix.Project
      def project, do: [app: :plug_cowboy_multipart, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
      def application, do: [extra_applications: [:logger]]
      defp deps, do: [{:plug_cowboy, "== 2.7.0"}, {:plug, "== 1.15.2"}]
    end
    """)

    File.write!(Path.join(dir, "lib/router.ex"), """
    defmodule PlugCowboyMultipart.Router do
      use Plug.Builder
      plug Plug.Parsers, parsers: [:urlencoded, :multipart]
      plug :dispatch
      def dispatch(conn, _opts), do: Plug.Conn.send_resp(conn, 200, "ok")
    end
    """)

    {"plug_cowboy_multipart", dir, "mix.lock",
     {"sh", ["-c", "mix deps.get && MIX_ENV=prod mix compile"], []}}
  end

  defp tesla_mint_hackney(dir) do
    File.mkdir_p!(Path.join(dir, "lib"))

    File.write!(Path.join(dir, "mix.exs"), """
    defmodule TeslaMintHackney.MixProject do
      use Mix.Project
      def project, do: [app: :tesla_mint_hackney, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
      def application, do: [extra_applications: [:logger]]
      defp deps, do: [{:tesla, "== 1.8.0"}, {:mint, "== 1.5.2"}, {:hackney, "== 1.18.1"}]
    end
    """)

    File.write!(Path.join(dir, "lib/client.ex"), """
    defmodule TeslaMintHackney.Client do
      use Tesla
      adapter Tesla.Adapter.Mint
      def ping, do: get("/")
    end
    """)

    {"tesla_mint_hackney", dir, "mix.lock",
     {"sh", ["-c", "mix deps.get && MIX_ENV=prod mix compile"], []}}
  end

  defp umbrella_three_apps(dir) do
    for app <- ~w(core api worker) do
      File.mkdir_p!(Path.join([dir, "apps", app, "lib"]))
    end

    File.write!(Path.join(dir, "mix.exs"), """
    defmodule UmbrellaThree.MixProject do
      use Mix.Project
      def project, do: [apps_path: "apps", version: "0.1.0", deps: []]
    end
    """)

    File.write!(Path.join(dir, "apps/core/mix.exs"), """
    defmodule Core.MixProject do
      use Mix.Project
      def project, do: [app: :core, version: "0.1.0", deps: [{:plug, "== 1.15.2"}]]
    end
    """)

    File.write!(Path.join(dir, "apps/core/lib/core.ex"), """
    defmodule Core do
      def parse(qs), do: Plug.Conn.Query.decode(qs)
    end
    """)

    File.write!(Path.join(dir, "apps/api/mix.exs"), """
    defmodule Api.MixProject do
      use Mix.Project
      def project, do: [app: :api, version: "0.1.0", deps: [{:core, in_umbrella: true}]]
    end
    """)

    File.write!(Path.join(dir, "apps/api/lib/api.ex"), """
    defmodule Api do
      def handle(qs), do: Core.parse(qs)
    end
    """)

    File.write!(Path.join(dir, "apps/worker/mix.exs"), """
    defmodule Worker.MixProject do
      use Mix.Project
      def project, do: [app: :worker, version: "0.1.0", deps: []]
    end
    """)

    File.write!(Path.join(dir, "apps/worker/lib/worker.ex"), """
    defmodule Worker do
      def work, do: :ok
    end
    """)

    {"umbrella_three_apps", dir, "mix.lock",
     {"sh", ["-c", "mix deps.get && MIX_ENV=prod mix compile"], []}}
  end

  defp rebar3_hackney(dir) do
    if System.find_executable("rebar3") do
      File.mkdir_p!(Path.join(dir, "src"))

      File.write!(Path.join(dir, "rebar.config"), """
      {deps, [{hackney, "1.18.1"}]}.
      """)

      File.write!(Path.join(dir, "src/rebar_app.app.src"), """
      {application, rebar_app, [{vsn, "0.1.0"}, {applications, [kernel, stdlib, hackney]}]}.
      """)

      {"rebar3_hackney", dir, "rebar.lock", {"rebar3", ["as", "prod", "compile"], []}}
    else
      nil
    end
  end
end

VulnCheck.Bench.RealWorld.main(System.argv())
