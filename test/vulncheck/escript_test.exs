defmodule VulnCheck.EscriptTest do
  # Builds the real escript; run with `mix test --include escript`.
  use ExUnit.Case, async: false

  alias VulnCheck.Test.{Project, Tmp}

  @moduletag :escript
  @moduletag timeout: 300_000

  @root Path.expand("../..", __DIR__)

  defp offline(root, cache),
    do: ["--project-dir", root, "--cache-dir", cache, "--offline", "--no-color", "--no-retired"]

  setup_all do
    {output, status} =
      System.cmd("mix", ["escript.build"],
        cd: @root,
        env: [{"MIX_ENV", "prod"}],
        stderr_to_stdout: true
      )

    assert status == 0, output
    %{bin: Path.join(@root, "vulncheck")}
  end

  test "prints version and help", %{bin: bin} do
    assert {"vulncheck " <> version, 0} = System.cmd(bin, ["--version"])
    assert String.trim(version) == VulnCheck.version()

    assert {help, 0} = System.cmd(bin, ["--help"])
    assert help =~ "vulncheck #{VulnCheck.version()} — reachability-aware"
    assert help =~ "--forbid-new-suppressions"

    assert {_, 2} = System.cmd(bin, ["--unknown-flag"], stderr_to_stdout: true)
  end

  test "scans Mix, rebar3 and Gleam projects", %{bin: bin} do
    cache = Project.cache!()

    mix = Project.shop!()
    assert {out, 1} = System.cmd(bin, offline(mix, cache))
    assert out =~ "[REACHABLE] CVE-2026-54892"

    rebar = Tmp.mkdir!("escript-rebar")
    Tmp.write!(rebar, "rebar.config", "{deps, [cowboy]}.\n")

    Tmp.write!(rebar, "rebar.lock", """
    {"1.2.0",
    [{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.12.0">>},0},
     {<<"plug">>,{pkg,<<"plug">>,<<"1.16.2">>},0}]}.
    [].
    """)

    assert {out, code} = System.cmd(bin, offline(rebar, cache))
    assert code == 1, out
    assert out =~ "Target: " and out =~ "(rebar3, OTP"
    assert out =~ "CVE-2026-54892"

    gleam = Tmp.mkdir!("escript-gleam")

    Tmp.write!(
      gleam,
      "gleam.toml",
      "name = \"storefront\"\nversion = \"1.0.0\"\n\n[dependencies]\ngleam_stdlib = \">= 0.34.0\"\n"
    )

    Tmp.write!(gleam, "manifest.toml", """
    packages = [
      { name = "gleam_stdlib", version = "0.40.0", build_tools = ["gleam"], requirements = [], otp_app = "gleam_stdlib", source = "hex", outer_checksum = "AAAA" },
    ]

    [requirements]
    gleam_stdlib = { version = ">= 0.34.0" }
    """)

    assert {out, 0} = System.cmd(bin, offline(gleam, cache))
    assert out =~ "Target: storefront (gleam, OTP"
    assert out =~ "No known advisories affect the locked dependencies."

    json_out = Path.join(Tmp.mkdir!("escript-out"), "r.json")
    assert {"", 1} = System.cmd(bin, offline(mix, cache) ++ ["-f", "json", "-o", json_out])
    assert %{"schema_version" => "1.0.0"} = json_out |> File.read!() |> JSON.decode!()
  end
end
