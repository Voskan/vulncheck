defmodule VulnCheck.Test.Project do
  @moduledoc false
  # A compiled Mix project calling into vulnerable Ash and Plug releases,
  # plus a pre-seeded feed cache so commands run offline.

  alias VulnCheck.Test.{Beams, Feeds, Tmp}

  @sha String.duplicate("a", 64)

  def shop!(opts \\ []) do
    root = Tmp.mkdir!("cli-shop")
    deps = Keyword.get(opts, :deps, [{"ash", "3.34.2"}, {"plug", "1.16.2"}])

    Tmp.write!(root, "mix.exs", """
    defmodule Shop.MixProject do
      use Mix.Project

      def project, do: [app: :shop, version: "0.1.0", deps: deps()]

      def application, do: [mod: {Shop.Application, []}]

      defp deps, do: [#{Enum.map_join(deps, ", ", fn {name, _} -> ~s({:#{name}, ">= 0.0.0"}) end)}]
    end
    """)

    lock =
      Enum.map_join(deps, "\n", fn {name, version} ->
        ~s(  "#{name}": {:hex, :#{name}, "#{version}", "#{@sha}", [:mix], [], "hexpm", "#{@sha}"},)
      end)

    Tmp.write!(root, "mix.lock", "%{\n#{lock}\n}\n")

    if Keyword.get(opts, :compile, true) and Enum.any?(deps, &(elem(&1, 0) == "plug")) do
      compile!(root)
    end

    root
  end

  defp compile!(root) do
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
         def decode_each(query, _acc), do: query
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

    Beams.write_app!(lib.("ash"), "ash")
    Beams.write_app!(lib.("plug"), "plug")

    Beams.write_app!(lib.("shop"), "shop",
      applications: [:kernel, :stdlib, :elixir, :ash, :plug],
      mod: "Elixir.Shop.Application"
    )
  end

  @doc "Writes the OSV archive and CVE records into `cache/feeds`."
  def seed_cache!(cache, opts \\ []) do
    feeds = Path.join(cache, "feeds")
    File.mkdir_p!(Path.join(feeds, "cves"))
    File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([Feeds.osv_ash(), Feeds.osv_plug()]))

    File.write!(
      Path.join(feeds, "cves/CVE-2026-101028.json"),
      JSON.encode!(
        Feeds.cve_record("CVE-2026-101028", "ash", ["'Elixir.Ash.Actions.Aggregate':run/4"])
      )
    )

    plug_routines =
      if Keyword.get(opts, :plug_routines, true),
        do: ["'Elixir.Plug.Conn.Query':decode/4"],
        else: []

    File.write!(
      Path.join(feeds, "cves/CVE-2026-54892.json"),
      JSON.encode!(Feeds.cve_record("CVE-2026-54892", "plug", plug_routines, modules: []))
    )

    cache
  end

  @doc "Fresh seeded cache directory."
  def cache!(opts \\ []), do: seed_cache!(Tmp.mkdir!("cli-cache"), opts)
end
