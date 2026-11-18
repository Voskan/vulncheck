defmodule VulnCheck.ScannerTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Config
  alias VulnCheck.Test.{Beams, Feeds, HTTPServer, Tmp}
  alias VulnCheck.Types.{Finding, MFA, ScanReport}

  @sha String.duplicate("a", 64)

  setup do
    root = Tmp.mkdir!("scan-project")

    Tmp.write!(root, "mix.exs", """
    defmodule Shop.MixProject do
      use Mix.Project

      def project, do: [app: :shop, version: "0.1.0", deps: deps()]

      def application, do: [mod: {Shop.Application, []}]

      defp deps, do: [{:ash, "~> 3.0"}, {:plug, "~> 1.16"}]
    end
    """)

    Tmp.write!(root, "mix.lock", """
    %{
      "ash": {:hex, :ash, "3.34.2", "#{@sha}", [:mix], [], "hexpm", "#{@sha}"},
      "plug": {:hex, :plug, "1.16.2", "#{@sha}", [:mix], [], "hexpm", "#{@sha}"},
    }
    """)

    lib = &Path.join(root, "_build/prod/lib/#{&1}/ebin")

    Beams.compile!(lib.("ash"), [
      {"ash.ex",
       """
       defmodule Ash do
         def read(query, opts), do: Ash.Actions.Read.run(query, opts)
         def count(query, opts), do: Ash.Actions.Aggregate.run(query, opts, :count, [])
       end

       defmodule Ash.Actions.Read do
         def run(query, _opts), do: query
       end

       defmodule Ash.Actions.Aggregate do
         def run(query, _opts, _kind, _extra), do: query
       end
       """}
    ])

    Beams.compile!(lib.("plug"), [
      {"query.ex",
       """
       defmodule Plug.Conn.Query do
         def decode(query, acc, _a, _b), do: decode_each(query, acc)
         def decode_each(query, _acc), do: split_keys(query, 1, 2, 3, 4, 5)
         def split_keys(query, _, _, _, _, _), do: query
       end
       """}
    ])

    Beams.compile!(lib.("shop"), [
      {"shop.ex",
       """
       defmodule Shop.Application do
         def start(_type, _args) do
           Shop.Catalog.list()
           Shop.Web.params("a=1")
           {:ok, self()}
         end
       end

       defmodule Shop.Catalog do
         def list, do: Ash.read(:products, [])
       end

       defmodule Shop.Web do
         def params(qs), do: Plug.Conn.Query.decode(qs, %{}, false, false)
       end
       """}
    ])

    Beams.write_app!(lib.("ash"), "ash", vsn: "3.34.2")
    Beams.write_app!(lib.("plug"), "plug", vsn: "1.16.2")

    Beams.write_app!(lib.("shop"), "shop",
      applications: [:kernel, :stdlib, :elixir, :ash, :plug],
      mod: "Elixir.Shop.Application"
    )

    zip = Feeds.zip([Feeds.osv_ash(), Feeds.osv_plug(), Feeds.osv_phoenix()])

    ash_cve =
      Feeds.cve_record("CVE-2026-101028", "ash", ["'Elixir.Ash.Actions.Aggregate':run/4"])

    plug_cve =
      Feeds.cve_record("CVE-2026-54892", "plug", [
        "'Elixir.Plug.Conn.Query':decode/4",
        "'Elixir.Plug.Conn.Query':split_keys/6"
      ])

    server =
      HTTPServer.start!(fn
        %{path: "/osv/all.zip"} -> {200, [], zip}
        %{path: "/cna/CVE-2026-101028.json"} -> {200, [], JSON.encode!(ash_cve)}
        %{path: "/cna/CVE-2026-54892.json"} -> {200, [], JSON.encode!(plug_cve)}
        _ -> {404, [], ""}
      end)

    opts = [
      osv_url: server.url <> "/osv/all.zip",
      cna_base_url: server.url <> "/cna",
      mitre_base_url: server.url <> "/mitre",
      hex_api_url: server.url <> "/hex"
    ]

    %{root: root, opts: opts}
  end

  test "scans a compiled project end to end", %{root: root, opts: opts} do
    config = %Config{project_dir: root, cache_dir: Tmp.mkdir!("scan-cache"), env: :prod}

    assert {:ok, %ScanReport{} = report} = VulnCheck.Scanner.run(config, opts)

    assert [plug, ash] = report.findings
    assert %Finding{package: "plug", verdict: :reachable, reason: :call_chain_proven} = plug
    assert plug.target_mfa == MFA.new("Elixir.Plug.Conn.Query", "decode", 4)
    assert plug.recommended_fix == "1.16.4"

    assert Enum.map(plug.trace, &MFA.format(&1.mfa)) == [
             "Shop.Application.start/2",
             "Shop.Web.params/1",
             "Plug.Conn.Query.decode/4"
           ]

    assert [
             %{file: "_build/prod/lib/shop/src/shop.ex", line: 4},
             %{file: "_build/prod/lib/shop/src/shop.ex", line: 14},
             %{file: "_build/prod/lib/plug/src/query.ex", line: 2}
           ] = plug.trace

    assert %Finding{package: "ash", verdict: :unreachable, reason: :function_not_called} = ash
    assert ash.fixed_versions == ["3.34.6"]

    assert report.summary.reachable == 1
    assert report.summary.unreachable == 1
    assert report.tool_version == VulnCheck.version()
    assert report.stats.modules >= 7
    assert report.stats.matched_advisories == 2
    assert report.stats.analysis.status == :complete
    assert is_map(report.stats.timings_ms)
    assert VulnCheck.should_fail?(report, config)

    # warm run: beam summaries come from the cache
    assert {:ok, warm} = VulnCheck.scan(config, opts)
    assert warm.stats.cached == warm.stats.beams
    assert Enum.map(warm.findings, & &1.fingerprint) == Enum.map(report.findings, & &1.fingerprint)
  end

  test "a dependency compiled for a different locked version cannot prove absence", ctx do
    ebin = Path.join(ctx.root, "_build/prod/lib/ash/ebin")
    Beams.write_app!(ebin, "ash", vsn: "3.34.6")

    {report, ash} = scan_ash(ctx)
    assert ash.verdict == :potentially_reachable
    assert ash.reason_detail =~ "lock specifies 3.34.2"
    assert report.stats.analysis.status == :partial
    assert hd(report.findings).package == "plug"
    assert hd(report.findings).verdict == :reachable
  end

  test "a missing or unreadable root BEAM keeps downstream matches active", ctx do
    ebin = Path.join(ctx.root, "_build/prod/lib/shop/ebin")

    Beams.write_app!(ebin, "shop",
      applications: [:ash, :plug],
      mod: "Elixir.Shop.Application",
      modules: ["Elixir.Shop.Application", "Elixir.Shop.Catalog", "Elixir.Shop.Web"]
    )

    File.rm!(Path.join(ebin, "Elixir.Shop.Catalog.beam"))
    File.write!(Path.join(ebin, "Elixir.Shop.Web.beam"), "invalid BEAM")

    {report, ash} = scan_ash(ctx)
    assert ash.verdict == :potentially_reachable
    assert ash.reason_detail =~ "missing compiled module Elixir.Shop.Catalog"
    assert Enum.any?(report.stats.analysis.issues, &String.contains?(&1, "could not read"))
    assert VulnCheck.should_fail?(report, %Config{})
  end

  test "a fallback Mix build reports the profile and keeps negative matches active", ctx do
    File.rename!(Path.join(ctx.root, "_build/prod"), Path.join(ctx.root, "_build/dev"))

    {report, ash} = scan_ash(ctx)
    assert ash.verdict == :potentially_reachable

    assert %{
             "analysis" => %{
               "status" => "unsuitable",
               "build_profile" => "dev",
               "issues" => ["compiled profile dev differs from requested environment prod"]
             }
           } = report |> VulnCheck.Report.JSON.render(%Config{}) |> JSON.decode!()
  end

  test "an incomplete intermediate boot application limits evidence to its dependency closure",
       ctx do
    lock = Path.join(ctx.root, "mix.lock")

    File.write!(
      lock,
      String.replace(
        File.read!(lock),
        "%{",
        ~s(%{\n  "relay": {:hex, :relay, "1.0.0", "#{@sha}", [:mix], [{:ash, ">= 0.0.0", [optional: false]}], "hexpm", "#{@sha}"},)
      )
    )

    Beams.write_app!(Path.join(ctx.root, "_build/prod/lib/shop/ebin"), "shop",
      applications: [:relay, :plug],
      mod: "Elixir.Shop.Application"
    )

    {report, ash} = scan_ash(ctx)
    assert ash.verdict == :potentially_reachable
    assert ash.reason_detail =~ "missing compiled .app for relay"
    assert hd(report.findings).verdict == :reachable
  end

  test "a partially compiled umbrella cannot prove routine absence", ctx do
    mix_exs = Path.join(ctx.root, "mix.exs")
    Tmp.write!(ctx.root, "apps/shop/mix.exs", File.read!(mix_exs))

    Tmp.write!(ctx.root, "apps/admin/mix.exs", """
    defmodule Admin.MixProject do
      use Mix.Project
      def project, do: [app: :admin, version: "0.1.0", deps: [{:ash, "~> 3.0"}]]
    end
    """)

    Tmp.write!(ctx.root, "mix.exs", """
    defmodule Umbrella.MixProject do
      use Mix.Project
      def project, do: [apps_path: "apps"]
    end
    """)

    {report, ash} = scan_ash(ctx)
    assert report.workspace.project_type == :umbrella
    assert ash.verdict == :potentially_reachable
    assert ash.reason_detail =~ "missing compiled .app for project application admin"
  end

  test "unresolved dispatch keeps a candidate potential only while its caller is reached", ctx do
    ash_ebin = Path.join(ctx.root, "_build/prod/lib/ash/ebin")
    shop_ebin = Path.join(ctx.root, "_build/prod/lib/shop/ebin")

    Beams.compile!(ash_ebin, [
      {"aggregate.ex",
       """
       defmodule Ash.Actions.Aggregate do
         def run(value, _, _, _), do: value
         def preview(value, _, _, _), do: value
       end
       """}
    ])

    Beams.compile!(shop_ebin, [
      {"catalog.ex",
       """
       defmodule Shop.Catalog do
         def list, do: Ash.read(:products, [])
         def invoke(function), do: apply(Ash.Actions.Aggregate, function, [0, 1, 2, 3])
       end
       """}
    ])

    {_, inactive} = scan_ash(ctx)
    assert inactive.reason == :function_not_called

    Beams.compile!(shop_ebin, [
      {"application.ex",
       """
       defmodule Shop.Application do
         def start(_, function), do: Shop.Catalog.invoke(function)
       end
       """}
    ])

    {active_report, active} = scan_ash(ctx)
    assert active.verdict == :potentially_reachable
    assert active.reason == :unresolved_dynamic_dispatch
    assert active.target_mfa == MFA.new("Elixir.Ash.Actions.Aggregate", "run", 4)
    assert List.last(active.trace).kind == :dynamic_candidate
    assert Enum.at(active.trace, -2).line == 3
    assert Enum.any?(active_report.warnings, &String.contains?(&1, "Shop.Catalog.invoke/1"))

    Beams.compile!(shop_ebin, [
      {"catalog.ex",
       """
       defmodule Shop.Catalog do
         def invoke(function) do
           apply(Ash.Actions.Aggregate, function, [0, 1, 2, 3])
           Ash.Actions.Aggregate.run(0, 1, 2, 3)
         end
       end
       """}
    ])

    {_, confirmed} = scan_ash(ctx)
    assert confirmed.verdict == :reachable
    assert confirmed.reason == :call_chain_proven
    assert Enum.at(confirmed.trace, -2).line == 4
  end

  defp scan_ash(%{root: root, opts: opts}) do
    config = %Config{project_dir: root, cache_dir: Tmp.mkdir!("scan-cache"), env: :prod}
    assert {:ok, report} = VulnCheck.scan(config, opts)
    assert %Finding{} = ash = Enum.find(report.findings, &(&1.package == "ash"))
    {report, ash}
  end

  test "keyword API, post-processing and error handling", %{root: root, opts: opts} do
    step = fn findings, %{config: %Config{}} ->
      {Enum.map(findings, &%{&1 | suppressed: &1.package == "plug"}), [], ["post step ran"]}
    end

    assert {:ok, report} =
             VulnCheck.scan(root,
               cache_dir: Tmp.mkdir!("scan-cache"),
               env: :prod,
               postprocess: [step],
               osv_url: opts[:osv_url],
               cna_base_url: opts[:cna_base_url],
               mitre_base_url: opts[:mitre_base_url],
               hex_api_url: opts[:hex_api_url]
             )

    assert report.summary.suppressed == 1
    assert "post step ran" in report.warnings

    Tmp.write!(root, ".vulncheck.ignore", """
    [%{id: "CVE-2026-54892", reason: "patched at the edge", expires: "2025-01-01"}]
    """)

    baseline = Path.join(Tmp.mkdir!("scan-baseline"), "base.json")

    config = %Config{
      project_dir: root,
      cache_dir: Tmp.mkdir!("scan-cache"),
      write_baseline: baseline
    }

    assert {:ok, with_ignore} = VulnCheck.scan(config, opts)
    assert [%{suppression_expired: true} | _] = with_ignore.findings

    assert with_ignore.policy_violations == [
             "suppression of EEF-CVE-2026-54892 (plug) expired on 2025-01-01"
           ]

    assert File.exists?(baseline)

    next_baseline = Path.join(Path.dirname(baseline), "next.json")

    assert {:ok, again} =
             VulnCheck.scan(%{config | write_baseline: next_baseline, baseline: baseline}, opts)

    assert [%{suppression_expired: true}] = again.findings
    assert again.all_findings == with_ignore.findings
    assert "1 finding(s) already present in the baseline" in again.warnings
    assert {:ok, [_, _]} = VulnCheck.Diff.read_baseline(next_baseline)
    refute VulnCheck.should_fail?(report, %Config{})

    empty = Tmp.mkdir!("scan-empty")
    assert {:error, {:unknown_project, _}} = VulnCheck.scan(empty, offline: true)

    assert {:error, {:feeds, :offline_cache_missing}} =
             VulnCheck.scan(root, cache_dir: Tmp.mkdir!("scan-cache"), offline: true)
  end
end
