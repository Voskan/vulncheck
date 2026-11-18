defmodule VulnCheck.WorkspaceTest do
  use ExUnit.Case, async: true

  alias VulnCheck.{Config, Workspace}
  alias VulnCheck.Test.Tmp
  alias VulnCheck.Workspace.{Detector, MixLock}

  @mix_lock ~S"""
  %{
    "bunt": {:hex, :bunt, "1.0.0", "081c2c665f086849e6d57900292b3a161727ab40431219529f13c4ddcf3e7a44", [:mix], [], "hexpm", "dc5f86aa08a5f6fa6b8096f0735c4e76d54ae5c9fa2c143e5a1fc7c1cd9bb6b5"},
    "credo": {:hex, :credo, "1.7.7", "771445037228f763f9b2afd612b6aa2fd8e28432a95dbbc60d8e03ce71ba4446", [:mix], [{:bunt, "~> 0.2.1 or ~> 1.0", [hex: :bunt, repo: "hexpm", optional: false]}, {:file_system, "~> 0.2 or ~> 1.0", [hex: :file_system, repo: "hexpm", optional: false]}, {:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: false]}], "hexpm", "8bc87496c9aaacdc3f90f01b7b0582467b69b4bd2441fe8aae3109d843cc2f2e"},
    "jason": {:hex, :jason, "1.4.4", "b9226785a9aa77b6857ca22832cffa5d5011a667207eb2a0ad56adb5db443b8a", [:mix], [{:decimal, "~> 1.0 or ~> 2.0", [hex: :decimal, repo: "hexpm", optional: true]}], "hexpm", "c5eb0cab91f094599f94d55bc63409236a8ec69a21a67814529e8d5f6cc90b3b"},
    "mime": {:hex, :mime, "2.0.6", "8f18486773d9b15f95f4f4f1e39b710045fa1de891fada4516559967276e4dc2", [:mix], [], "hexpm"},
    "plug": {:hex, :plug, "1.16.2", "1c4a2b8e1a7a0b6e3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", [:mix], [{:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: true]}, {:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}, {:plug_crypto, "~> 1.1.1 or ~> 1.2 or ~> 2.0", [hex: :plug_crypto, repo: "hexpm", optional: false]}]},
    "plug_crypto": {:hex, :plug_crypto, "2.1.0", "f44309c2b06d249c27c8d3f65cfe08158ade08418cf540fd4f72d4d6863abb7b", [:mix], []},
    "postgrex": {:hex, :postgrex, "0.19.1", "73b498508b69aded53907fe48a1fee811be34cc720e69ef4ccd568c8715495ea", [:mix], [{:decimal, "~> 1.5 or ~> 2.0", [hex: :decimal, repo: "hexpm", optional: true]}, {:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: true]}], "hexpm", "8bac7885a18f381e091ec6caf41bda7bb8c77912bb0e9285212829afe5d8a8f8"},
    "file_system": {:hex, :file_system, "1.0.1", "79e8ceaddb0416f8b8cd02a0127bdbababe7bf4a23d2a395b983c1f8b3f73edd", [:mix], [], "hexpm", "4414d1f38863ddf9120720cd976fce5bdde8e91d8283353f0e31850fa89feb9e"},
    "my_fork": {:git, "https://github.com/acme/my_fork.git", "5f3c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f", [branch: "main"]},
    "tagged": {:git, "https://github.com/acme/tagged.git", "0123456789abcdef0123456789abcdef01234567", [tag: "v2.1.0"]},
  }
  """

  @mix_exs ~S"""
  defmodule Shop.MixProject do
    use Mix.Project

    def project do
      [app: :shop, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
    end

    defp deps do
      [
        {:plug, "~> 1.16"},
        {:jason, "~> 1.4"},
        {:postgrex, ">= 0.0.0"},
        {:my_fork, github: "acme/my_fork"},
        {:tagged, git: "https://github.com/acme/tagged.git", tag: "v2.1.0"},
        {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
        {:file_system, "~> 1.0", only: :dev}
      ]
    end
  end
  """

  defp config(dir, extra \\ []) do
    {:ok, config} = Config.from_cli_and_file(["--project-dir", dir] ++ extra)
    config
  end

  describe "MixLock.parse/1" do
    test "parses 8-, 7- and 6-element Hex tuples and git entries" do
      assert {:ok, packages} = MixLock.parse(@mix_lock)

      assert %{version: "1.16.2", source: :hex, checksum: nil, hex_name: "plug"} =
               packages["plug"]

      assert packages["bunt"].checksum ==
               "dc5f86aa08a5f6fa6b8096f0735c4e76d54ae5c9fa2c143e5a1fc7c1cd9bb6b5"

      assert packages["mime"].checksum == nil
      assert packages["plug_crypto"].inner_checksum =~ "f44309"

      assert %{source: :git, git_ref: "5f3c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"} =
               packages["my_fork"]

      assert packages["my_fork"].version == "5f3c0a1b2c3d"
      assert packages["tagged"].version == "2.1.0"
      assert packages["plug"].lock_line == 6
    end

    test "links optional deps only when present in the lockfile" do
      {:ok, packages} = MixLock.parse(@mix_lock)
      assert Enum.sort(packages["plug"].deps) == ["jason", "mime", "plug_crypto"]
      assert packages["jason"].deps == []
      assert packages["jason"].optional_deps == ["decimal"]
      assert packages["postgrex"].deps == ["jason"]
    end

    test "rejects code and malformed lockfiles without creating atoms" do
      assert {:error, msg} = MixLock.parse(~S|%{"x": File.rm_rf!("/")}|)
      assert msg =~ "unexpected expression"
      assert {:error, _} = MixLock.parse("[1, 2]")
      assert {:error, _} = MixLock.parse("%{")
      assert {:error, msg} = MixLock.parse_file("/nonexistent/mix.lock")
      assert msg =~ "mix.lock"
    end
  end

  describe "Detector" do
    test "detects project kinds and missing lockfiles" do
      dir = Tmp.mkdir!("detect")
      assert {:error, :unknown_project, _} = Detector.detect(dir)

      Tmp.write!(dir, "mix.exs", @mix_exs)
      assert {:error, :lockfile_not_found, details} = Detector.detect(dir)
      assert details =~ "mix.lock"

      Tmp.write!(dir, "mix.lock", @mix_lock)
      assert {:ok, %{type: :mix}} = Detector.detect(dir)

      gleam = Tmp.mkdir!("detect-gleam")
      Tmp.write!(gleam, "gleam.toml", "name = \"x\"\n")
      assert {:error, :lockfile_not_found, _} = Detector.detect(gleam)

      rebar = Tmp.mkdir!("detect-rebar")
      Tmp.write!(rebar, "rebar.config", "{deps, []}.\n")
      Tmp.write!(rebar, "rebar.lock", "[].\n")
      assert {:ok, %{type: :rebar3}} = Detector.detect(rebar)
    end
  end

  describe "Mix projects" do
    test "splits :prod and :non_prod transitively" do
      dir = Tmp.mkdir!("mix-scope")
      Tmp.write!(dir, "mix.exs", @mix_exs)
      Tmp.write!(dir, "mix.lock", @mix_lock)

      assert {:ok, ws} = Workspace.load(config(dir))
      assert ws.project_type == :mix
      assert ws.project_name == "shop"
      assert ws.root_apps == ["shop"]
      assert "plug" in ws.direct_deps and "my_fork" in ws.direct_deps
      refute "mime" in ws.direct_deps
      assert ws.direct_deps == Enum.sort(ws.direct_deps)
      assert ws.otp_release == System.otp_release()
      assert ws.elixir_version == System.version()

      scopes = Map.new(ws.packages, fn {name, pkg} -> {name, pkg.scope} end)

      assert scopes["plug"] == :prod
      assert scopes["mime"] == :prod
      assert scopes["plug_crypto"] == :prod
      # needed by both the prod root and credo: stays :prod
      assert scopes["jason"] == :prod
      assert scopes["postgrex"] == :prod
      assert scopes["my_fork"] == :prod
      assert scopes["credo"] == :non_prod
      assert scopes["bunt"] == :non_prod
      assert scopes["file_system"] == :non_prod

      assert [_ | _] = ws.warnings
      assert ws.build_dir == nil
    end

    test "--env test pulls test-only dependencies into the target closure" do
      dir = Tmp.mkdir!("mix-env")
      Tmp.write!(dir, "mix.exs", @mix_exs)
      Tmp.write!(dir, "mix.lock", @mix_lock)

      assert {:ok, ws} = Workspace.load(config(dir, ["--env", "test"]))
      scopes = Map.new(ws.packages, fn {name, pkg} -> {name, pkg.scope} end)

      # credo is part of the test environment but declared runtime: false;
      # its own dependencies only serve it
      assert scopes["credo"] == :build_only
      assert scopes["bunt"] == :build_only
      assert scopes["file_system"] == :build_only
      # needed by credo and by the runtime closure: stays :prod
      assert scopes["jason"] == :prod
      assert scopes["plug"] == :prod
    end

    test "runtime: false dependencies and their own dependencies are build-time only" do
      dir = Tmp.mkdir!("mix-runtime-false")

      Tmp.write!(
        dir,
        "mix.exs",
        String.replace(
          @mix_exs,
          ~s({:credo, "~> 1.7", only: [:dev, :test], runtime: false}),
          ~s({:credo, "~> 1.7", runtime: false})
        )
      )

      Tmp.write!(dir, "mix.lock", @mix_lock)

      assert {:ok, ws} = Workspace.load(config(dir))
      scopes = Map.new(ws.packages, fn {name, pkg} -> {name, pkg.scope} end)

      assert scopes["credo"] == :build_only
      assert scopes["bunt"] == :build_only
      # file_system is also a :dev dependency; build-time use wins
      assert scopes["file_system"] == :build_only
      assert scopes["jason"] == :prod
      assert ws.packages["credo"] in VulnCheck.Types.Workspace.non_prod_packages(ws)
      refute ws.packages["credo"] in VulnCheck.Types.Workspace.prod_packages(ws)
    end

    test "uses compiled ebin directories with a build fallback and .app applications" do
      dir = Tmp.mkdir!("mix-build")
      Tmp.write!(dir, "mix.exs", @mix_exs)
      Tmp.write!(dir, "mix.lock", @mix_lock)

      Tmp.write!(dir, "_build/dev/lib/plug/ebin/plug.app", """
      {application,plug,[{applications,[kernel,stdlib,elixir,logger,mime,plug_crypto,telemetry]},
       {description,"Compose web applications"},{vsn,"1.16.2"},{mod,{'Elixir.Plug.Application',[]}}]}.
      """)

      Tmp.write!(dir, "_build/dev/lib/shop/ebin/shop.app", """
      {application,shop,[{applications,[kernel,stdlib,elixir,plug]},{vsn,"0.1.0"},{mod,{'Elixir.Shop.Application',[]}}]}.
      """)

      assert {:ok, ws} = Workspace.load(config(dir))
      assert ws.build_env == "dev"
      assert ws.build_dir == Path.join([dir, "_build", "dev"])
      assert [warning] = ws.warnings
      assert warning =~ "_build/prod not found"
      assert ws.packages["plug"].ebin_dir == Path.join([dir, "_build/dev/lib/plug/ebin"])
      assert ws.packages["bunt"].ebin_dir == nil
      assert ws.root_ebin_dirs == [Path.join([dir, "_build/dev/lib/shop/ebin"])]
    end

    test "treats unparseable dependency declarations conservatively" do
      dir = Tmp.mkdir!("mix-dynamic")

      Tmp.write!(dir, "mix.exs", """
      defmodule Dyn.MixProject do
        use Mix.Project
        def project, do: [app: :dyn, deps: Dyn.Deps.all()]
      end
      """)

      Tmp.write!(dir, "mix.lock", @mix_lock)
      assert {:ok, ws} = Workspace.load(config(dir))
      assert Enum.all?(ws.packages, fn {_name, pkg} -> pkg.scope == :prod end)
      assert Enum.any?(ws.warnings, &(&1 =~ "built dynamically"))
    end

    test "follows path dependencies" do
      dir = Tmp.mkdir!("mix-path")

      Tmp.write!(dir, "app/mix.exs", """
      defmodule App.MixProject do
        use Mix.Project
        def project, do: [app: :app, deps: [{:shared, path: "../shared"}, {:credo, "~> 1.7", only: :dev}]]
      end
      """)

      Tmp.write!(dir, "shared/mix.exs", """
      defmodule Shared.MixProject do
        use Mix.Project
        @version "0.4.0"
        def project, do: [app: :shared, version: @version, deps: [{:plug, "~> 1.16"}]]
      end
      """)

      Tmp.write!(dir, "app/mix.lock", @mix_lock)

      assert {:ok, ws} = Workspace.load(config(Path.join(dir, "app")))
      assert %{source: :path, version: "0.4.0", scope: :prod} = ws.packages["shared"]
      assert ws.packages["plug"].scope == :prod
      assert ws.packages["credo"].scope == :non_prod
    end
  end

  describe "Umbrella projects" do
    test "combines the dependencies of every child app" do
      dir = Tmp.mkdir!("umbrella")

      Tmp.write!(dir, "mix.exs", """
      defmodule Platform.MixProject do
        use Mix.Project
        def project, do: [apps_path: "apps", version: "0.1.0", deps: deps()]
        defp deps, do: [{:credo, "~> 1.7", only: [:dev, :test], runtime: false}]
      end
      """)

      Tmp.write!(dir, "apps/api/mix.exs", """
      defmodule Api.MixProject do
        use Mix.Project
        def project, do: [app: :api, deps: [{:plug, "~> 1.16"}, {:worker, in_umbrella: true}]]
      end
      """)

      Tmp.write!(dir, "apps/worker/mix.exs", """
      defmodule Worker.MixProject do
        use Mix.Project
        def project, do: [app: :worker, deps: [{:postgrex, ">= 0.0.0"}, {:file_system, "~> 1.0", only: :test}]]
      end
      """)

      Tmp.write!(dir, "mix.lock", @mix_lock)

      assert {:ok, ws} = Workspace.load(config(dir))
      assert ws.project_type == :umbrella
      assert ws.project_name == Path.basename(dir)
      assert ws.root_apps == ["api", "worker"]
      assert ws.packages["plug"].scope == :prod
      assert ws.packages["postgrex"].scope == :prod
      assert ws.packages["jason"].scope == :prod
      assert ws.packages["credo"].scope == :non_prod
      assert ws.packages["bunt"].scope == :non_prod
      assert ws.packages["file_system"].scope == :non_prod
    end
  end

  describe "rebar3 projects" do
    test "parses rebar.lock with checksums and finds ebin directories" do
      dir = Tmp.mkdir!("rebar")
      Tmp.write!(dir, "rebar.config", "{deps, [cowboy]}.\n")

      Tmp.write!(dir, "rebar.lock", """
      {"1.2.0",
      [{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.12.0">>},0},
       {<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.13.0">>},1},
       {<<"ranch">>,{pkg,<<"ranch">>,<<"1.8.0">>},1},
       {<<"my_git">>,{git,"https://github.com/acme/my_git.git",{ref,"2f2c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"}},0}]}.
      [
      {pkg_hash,[
       {<<"cowboy">>, <<"8A7ABE6D183372CEB21CAA2709BEC928AB2B72E18A3911AA1771639BEF82651E">>},
       {<<"cowlib">>, <<"DB8F7505D8332D98EF50A3EF34B34C1C58DDB7ADB98CF6D9DCD08E7EF4C9E7D0">>}]},
      {pkg_hash_ext,[
       {<<"cowboy">>, <<"7D4F5E1D27BCC5D2A1F2E1F3A1B2C3D4E5F60718293A4B5C6D7E8F9A0B1C2D3E">>}]}
      ].
      """)

      Tmp.write!(dir, "src/edge.app.src", """
      {application, edge, [{vsn, "1.0.0"}, {applications, [kernel, stdlib, cowboy]}, {mod, {edge_app, []}}]}.
      """)

      Tmp.write!(dir, "_build/default/lib/cowboy/ebin/cowboy.app", """
      {application,cowboy,[{applications,[kernel,stdlib,crypto,cowlib,ranch]},{vsn,"2.12.0"}]}.
      """)

      Tmp.write!(dir, "_build/default/lib/edge/ebin/edge.app", "{application,edge,[]}.\n")

      assert {:ok, ws} = Workspace.load(config(dir))
      assert ws.project_type == :rebar3
      assert ws.project_name == "edge"
      assert ws.root_apps == ["edge"]
      assert ws.direct_deps == ["cowboy", "my_git"]
      assert ws.build_env == "default"
      assert ws.root_ebin_dirs == [Path.join(dir, "_build/default/lib/edge/ebin")]

      cowboy = ws.packages["cowboy"]
      assert cowboy.version == "2.12.0"
      assert cowboy.checksum == "7d4f5e1d27bcc5d2a1f2e1f3a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e"
      assert cowboy.inner_checksum =~ "8a7abe6d"
      assert Enum.sort(cowboy.deps) == ["cowlib", "ranch"]
      assert cowboy.ebin_dir == Path.join(dir, "_build/default/lib/cowboy/ebin")
      assert cowboy.lock_line == 2
      assert ws.packages["cowlib"].checksum =~ "db8f7505"
      assert %{source: :git, git_ref: "2f2c0a1b" <> _} = ws.packages["my_git"]
      assert Enum.all?(ws.packages, fn {_, pkg} -> pkg.scope == :prod end)
    end

    test "supports the legacy bare-list format" do
      assert {:ok, packages} =
               VulnCheck.Workspace.RebarLock.parse(
                 "[{<<\"jsx\">>,{pkg,<<\"jsx\">>,<<\"2.8.0\">>},0}].\n"
               )

      assert packages["jsx"].version == "2.8.0"
      assert {:error, _} = VulnCheck.Workspace.RebarLock.parse("foo.\n")
    end
  end

  describe "Gleam projects" do
    test "splits dependencies and dev-dependencies" do
      dir = Tmp.mkdir!("gleam")

      Tmp.write!(dir, "gleam.toml", """
      name = "storefront"
      version = "1.0.0"

      [dependencies]
      gleam_stdlib = ">= 0.34.0 and < 2.0.0"
      mist = ">= 1.0.0 and < 2.0.0"

      [dev-dependencies]
      gleeunit = ">= 1.0.0 and < 2.0.0"
      """)

      Tmp.write!(dir, "manifest.toml", """
      # This file was generated by Gleam
      packages = [
        { name = "gleam_stdlib", version = "0.40.0", build_tools = ["gleam"], requirements = [], otp_app = "gleam_stdlib", source = "hex", outer_checksum = "86606B75A600BBD05E539EAEABAB4BEFBDDE6A3F3B5D3D2D3AC6C7D1DF5D0E7A" },
        { name = "gleam_erlang", version = "0.27.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], otp_app = "gleam_erlang", source = "hex", outer_checksum = "AAAA" },
        { name = "mist", version = "1.2.0", build_tools = ["gleam"], requirements = [
          "gleam_erlang",
          "gleam_stdlib",
        ], otp_app = "mist", source = "hex", outer_checksum = "BBBB" },
        { name = "gleeunit", version = "1.2.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], otp_app = "gleeunit", source = "hex", outer_checksum = "CCCC" },
      ]

      [requirements]
      gleam_stdlib = { version = ">= 0.34.0 and < 2.0.0" }
      """)

      Tmp.write!(dir, "build/dev/erlang/mist/ebin/mist.app", "{application,mist,[]}.\n")

      assert {:ok, ws} = Workspace.load(config(dir))
      assert ws.project_type == :gleam
      assert ws.project_name == "storefront"
      assert ws.packages["mist"].scope == :prod
      assert ws.packages["gleam_erlang"].scope == :prod
      assert ws.packages["gleam_stdlib"].scope == :prod
      assert ws.packages["gleeunit"].scope == :non_prod
      assert ws.packages["mist"].checksum == "bbbb"
      assert ws.packages["mist"].ebin_dir == Path.join(dir, "build/dev/erlang/mist/ebin")
      assert ws.build_env == "dev"
    end

    test "supports [[packages]] tables" do
      assert {:ok, packages} =
               VulnCheck.Workspace.GleamManifest.parse_manifest("""
               [[packages]]
               name = "wisp"
               version = "0.15.0"
               source = "hex"
               requirements = ["mist"]

               [[packages]]
               name = "mist"
               version = "1.2.0"
               source = "hex"
               """)

      assert packages["wisp"].deps == ["mist"]
      assert packages["mist"].version == "1.2.0"
    end
  end

  test "load/1 reports missing lockfiles" do
    dir = Tmp.mkdir!("nolock")
    Tmp.write!(dir, "mix.exs", @mix_exs)
    assert {:error, {:lockfile_not_found, _}} = Workspace.load(config(dir))
  end

  test "--otp-version overrides the runtime release" do
    dir = Tmp.mkdir!("otp")
    Tmp.write!(dir, "mix.exs", @mix_exs)
    Tmp.write!(dir, "mix.lock", @mix_lock)
    assert {:ok, %{otp_release: "25"}} = Workspace.load(config(dir, ["--otp-version", "25"]))
  end
end
