defmodule VulnCheck.PerformanceInvariantsTest do
  # Guarantees behind the published benchmark numbers: advisory parsing and
  # warm scans never grow the atom table, and a warm `.beam` cache never
  # re-reads chunks of unchanged files. Not async: the atom table and call
  # count tracing are VM-global.
  use ExUnit.Case, async: false

  import VulnCheck.Test.FixtureBuilder

  alias VulnCheck.Beam.{AbstractWalker, Loader}
  alias VulnCheck.Cache
  alias VulnCheck.Feeds.{EefCna, OSV}
  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary}

  @chunks {:beam_lib, :chunks, 2}

  @plug %{
    name: "plug",
    version: "1.16.0",
    ex: [
      {"lib/plug/parsers/multipart.ex",
       """
       defmodule Plug.Parsers.MULTIPART do
         def init(opts), do: Keyword.put_new(opts, :length, 8_000_000)
       end
       """}
    ]
  }

  defp shop! do
    mix_project!("shop",
      mod: "Shop.Application",
      applications: [:plug],
      packages: [@plug],
      ex: [
        {"lib/shop/application.ex",
         """
         defmodule Shop.Application do
           def start(_type, _args), do: Shop.Router.init([])
         end
         """},
        {"lib/shop/router.ex",
         """
         defmodule Shop.Router do
           def init(opts), do: Plug.Parsers.MULTIPART.init(opts)
         end
         """}
      ]
    )
  end

  # -- synthetic advisories ----------------------------------------------------

  # OSV records and CVE 5.1 records naming modules and functions that exist
  # nowhere: the token makes every name new to this VM.
  defp advisories(count) do
    token = Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    for i <- 1..count do
      module = "Elixir.Unseen#{token}.Mod#{i}"
      erlang_module = "unseen_#{token}_#{i}"
      function = "handle_#{token}_#{i}"
      package = "unseen_pkg_#{token}_#{i}"
      cve = "CVE-2026-#{900_000 + i}"

      osv = %{
        "id" => "EEF-#{cve}",
        "aliases" => [cve],
        "summary" => "#{module}.#{function}/2 mishandles input",
        "details" => "Only exploitable when running on OTP 25 or earlier.",
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => package},
            "ranges" => [
              %{
                "type" => "SEMVER",
                "events" => [%{"introduced" => "0"}, %{"fixed" => "1.#{i}.0"}]
              }
            ],
            "ecosystem_specific" => %{
              "modules" => [module, erlang_module],
              "affected_functions" => [
                "#{module}.#{function}/2",
                "#{erlang_module}:#{function}/1",
                %{"name" => "'#{erlang_module}':#{function}_alt/3"}
              ]
            }
          }
        ],
        "severity" => [
          %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
        "database_specific" => %{"cwe_ids" => ["CWE-#{i}"], "severity" => "HIGH"}
      }

      cve_record = %{
        "containers" => %{
          "cna" => %{
            "affected" => [
              %{
                "packageName" => package,
                "packageURL" => "pkg:hex/#{package}",
                "modules" => [module, "Elixir.Unseen#{token}.Extra#{i}"],
                "programRoutines" => [
                  %{"name" => "'#{module}':#{function}_cve/4"},
                  %{"name" => "#{erlang_module}:#{function}_cve/0"}
                ],
                "versions" => [
                  %{
                    "version" => "0.1.0",
                    "lessThan" => "1.#{i}.0",
                    "status" => "affected",
                    "versionType" => "semver"
                  }
                ]
              }
            ],
            "descriptions" => [%{"lang" => "en", "value" => "Affects OTP 26 and later."}],
            "metrics" => [
              %{"cvssV3_1" => %{"baseScore" => 7.5, "baseSeverity" => "HIGH"}}
            ],
            "problemTypes" => [
              %{"descriptions" => [%{"cweId" => "CWE-#{1000 + i}", "type" => "CWE"}]}
            ]
          }
        }
      }

      {"EEF-#{cve}.json", JSON.encode!(osv), cve_record}
    end
  end

  defp parse!(records) do
    files = for {name, json, _cve} <- records, do: {String.to_charlist(name), json}
    {:ok, {_name, zip}} = :zip.create(~c"osv.zip", files, [:memory])
    {:ok, parsed} = OSV.parse_archive(zip)

    cves = Map.new(records, fn {name, _json, cve} -> {Path.rootname(name), cve} end)
    Enum.map(parsed, &EefCna.apply_record(&1, Map.fetch!(cves, &1.id)))
  end

  test "parsing 500 advisories with unseen module and function names creates no atoms" do
    # warm-up with a different set loads every module on the parsing path
    _ = parse!(advisories(20))

    records = advisories(500)
    before = :erlang.system_info(:atom_count)
    parsed = parse!(records)
    assert :erlang.system_info(:atom_count) - before == 0

    assert length(parsed) == 500
    advisory = hd(parsed)
    assert advisory.enriched
    assert advisory.symbol_source == :cve
    assert length(advisory.affected_routines) == 2
    assert length(advisory.affected_modules) == 3
    assert Enum.all?(advisory.affected_routines, &is_binary(&1.module))
    assert Enum.all?(advisory.affected_routines, &is_binary(&1.function))
  end

  # -- warm scans ----------------------------------------------------------------

  test "repeated warm scans create no atoms" do
    root = shop!()
    cache = feed_cache!()
    scan = fn -> scan!(root, cache_dir: cache) end

    first = scan.()
    assert finding!(first, "EEF-CVE-2026-60101").verdict == :reachable
    _ = scan.()

    before = :erlang.system_info(:atom_count)
    for _ <- 1..5, do: scan.()
    assert :erlang.system_info(:atom_count) - before == 0
  end

  test "a warm cache serves every unchanged .beam without reading its chunks" do
    root = shop!()
    cache = feed_cache!()

    cold = scan!(root, cache_dir: cache)
    assert cold.stats.analyzed == cold.stats.beams
    assert cold.stats.beams > 0

    :erlang.trace_pattern(@chunks, true, [:call_count])

    warm =
      try do
        scan!(root, cache_dir: cache)
      after
        {:call_count, calls} = :erlang.trace_info(@chunks, :call_count)
        :erlang.trace_pattern(@chunks, false, [:call_count])
        send(self(), {:chunk_calls, calls})
      end

    assert_received {:chunk_calls, 0}
    assert warm.stats.cached == warm.stats.beams
    assert warm.stats.analyzed == 0
    assert warm.findings == cold.findings
  end

  test "a changed .beam misses the cache; the others still hit" do
    root = shop!()
    cache = feed_cache!()
    cold = scan!(root, cache_dir: cache)

    router = Path.join(root, "_build/prod/lib/shop/ebin/Elixir.Shop.Router.beam")
    {:ok, _module, chunks} = :beam_lib.all_chunks(String.to_charlist(router))
    {:ok, rebuilt} = :beam_lib.build_module(chunks ++ [{~c"Xtra", <<0>>}])
    File.write!(router, rebuilt)

    warm = scan!(root, cache_dir: cache)
    assert warm.stats.analyzed == 1
    assert warm.stats.cached == cold.stats.beams - 1
  end

  # -- the atom vocabulary of cached summaries ----------------------------------

  test "cached summaries only hold atoms defined by the modules loaded before decoding" do
    # Read the on-disk compilation even when coverage instruments the loaded modules.
    ebin = Mix.Project.compile_path()

    # `Loader` loads these before the first `binary_to_term(bin, [:safe])`;
    # an atom outside their tables would turn a fresh VM's cache hits into misses
    vocabulary =
      [ModuleSummary, CallEdge, DynamicCall, MFA, AbstractWalker, Cache, Loader]
      |> Enum.flat_map(fn module ->
        beam = ebin |> Path.join("#{module}.beam") |> String.to_charlist()
        {:ok, {^module, [atoms: atoms]}} = :beam_lib.chunks(beam, [:atoms])
        Enum.map(atoms, &elem(&1, 1))
      end)
      |> MapSet.new()
      |> MapSet.union(MapSet.new([true, false, nil]))

    dirs = [
      {nil, Path.join(:code.lib_dir(:elixir), "ebin")},
      {nil, ebin}
    ]

    result = Loader.load_dirs(dirs, cache: false)
    assert result.stats.analyzed > 300

    stray =
      result.modules
      |> Map.values()
      |> Enum.flat_map(fn summary ->
        term = {:vulncheck_beam, 0, "", %{summary | beam_path: nil}}
        term |> atoms() |> Enum.reject(&MapSet.member?(vocabulary, &1))
      end)
      |> Enum.uniq()

    assert stray == []
  end

  defp atoms(term) when is_atom(term), do: [term]
  defp atoms(term) when is_list(term), do: Enum.flat_map(term, &atoms/1)
  defp atoms(term) when is_tuple(term), do: term |> Tuple.to_list() |> atoms()
  defp atoms(%{} = map), do: map |> Map.to_list() |> atoms()
  defp atoms(_term), do: []
end
