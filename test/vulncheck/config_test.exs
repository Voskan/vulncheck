defmodule VulnCheck.ConfigTest do
  use ExUnit.Case, async: false

  alias VulnCheck.Config
  alias VulnCheck.Test.Tmp
  alias VulnCheck.Types.MFA

  setup do
    %{dir: Tmp.mkdir!("config")}
  end

  test "defaults apply when there is no .vulncheck.exs", %{dir: dir} do
    assert {:ok, config} = Config.from_cli_and_file(["--project-dir", dir])
    assert config.project_dir == dir
    assert config.env == :prod
    assert config.format == :terminal
    assert config.fail_on == :potentially_reachable
    assert config.min_severity == :low
    assert config.fail_on_retired
    assert config.cache_ttl_seconds == 3600
    assert config.ignore_file == ".vulncheck.ignore"
  end

  test "reads a valid declarative .vulncheck.exs", %{dir: dir} do
    Tmp.write!(dir, ".vulncheck.exs", """
    [
      env: :prod,
      fail_on: :reachable,
      min_severity: :high,
      fail_on_retired: false,
      configured_adapters: [tesla: Tesla.Adapter.Mint, swoosh: [Swoosh.Adapters.Sendgrid]],
      extra_entrypoints: [{MyApp.ReleaseTasks, :migrate, 0}, "MyApp.Rpc.handle/2"],
      ignore_file: "security/.vulncheck.ignore",
      require_ignore_reason: true,
      require_ignore_expiry: true,
      cache_dir: nil,
      cache_ttl_seconds: 120,
      otp_version: 26
    ]
    """)

    assert {:ok, config} = Config.from_cli_and_file(["--project-dir", dir])
    assert config.fail_on == :reachable
    assert config.min_severity == :high
    refute config.fail_on_retired
    assert config.require_ignore_expiry
    assert config.cache_ttl_seconds == 120
    assert config.otp_version == "26"
    assert config.ignore_file == "security/.vulncheck.ignore"

    assert config.configured_adapters == %{
             tesla: ["Elixir.Tesla.Adapter.Mint"],
             swoosh: ["Elixir.Swoosh.Adapters.Sendgrid"]
           }

    assert config.extra_entrypoints == [
             MFA.new("Elixir.MyApp.ReleaseTasks", "migrate", 0),
             MFA.new("Elixir.MyApp.Rpc", "handle", 2)
           ]

    assert Config.ignore_path(config) == Path.join(dir, "security/.vulncheck.ignore")
  end

  test "refuses to execute code inside .vulncheck.exs", %{dir: dir} do
    marker = Path.join(dir, "executed")

    Tmp.write!(dir, ".vulncheck.exs", """
    [
      fail_on: :reachable,
      cache_dir: System.cmd("whoami", []) |> elem(0),
      env: File.write!(#{inspect(marker)}, "pwned")
    ]
    """)

    assert {:error, message} = Config.from_cli_and_file(["--project-dir", dir])
    assert message =~ "only literal values are allowed"
    assert message =~ "System.cmd"
    refute File.exists?(marker)
  end

  test "rejects unknown keys, bad values and syntax errors", %{dir: dir} do
    Tmp.write!(dir, ".vulncheck.exs", "[unknown_key: true]")
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
    assert msg =~ "unknown configuration key"

    Tmp.write!(dir, ".vulncheck.exs", "[fail_on: :sometimes]")
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
    assert msg =~ "invalid value :sometimes"

    Tmp.write!(dir, ".vulncheck.exs", "[configured_adapters: [mystery: Foo]]")
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
    assert msg =~ "unknown adapter family"

    Tmp.write!(dir, ".vulncheck.exs", "[fail_on: ")
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
    assert msg =~ "syntax error"

    Tmp.write!(dir, ".vulncheck.exs", "%{fail_on: :any}")
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
    assert msg =~ "keyword list"
  end

  test "parsing the config file does not create atoms", %{dir: dir} do
    # Warm up lazily loaded modules before measuring.
    Tmp.write!(dir, ".vulncheck.exs", "[extra_entrypoints: [{Warm.Up, :warm, 0}]]")
    assert {:ok, _config} = Config.from_cli_and_file(["--project-dir", dir])

    Tmp.write!(dir, ".vulncheck.exs", """
    [extra_entrypoints: [{ZzNeverSeen#{System.unique_integer([:positive])}.Mod, :zz_unseen_fun_x, 0}]]
    """)

    before = :erlang.system_info(:atom_count)
    assert {:ok, _config} = Config.from_cli_and_file(["--project-dir", dir])
    assert :erlang.system_info(:atom_count) == before
  end

  test "CLI flags take precedence over .vulncheck.exs", %{dir: dir} do
    Tmp.write!(dir, ".vulncheck.exs", "[fail_on: :reachable, format: :json, min_severity: :high]")

    argv = [
      "--project-dir",
      dir,
      "--fail-on",
      "any",
      "--format",
      "sarif",
      "--min-severity",
      "medium",
      "--no-color",
      "--show-unreachable",
      "--otp-version",
      "25",
      "--offline",
      "-o",
      "out.sarif",
      "--no-retired"
    ]

    assert {:ok, config} = Config.from_cli_and_file(argv, cwd: dir)
    assert config.fail_on == :any
    assert config.format == :sarif
    assert config.min_severity == :medium
    refute config.color
    assert config.show_unreachable
    assert config.otp_version == "25"
    assert config.offline
    # paths on the command line are relative to the working directory
    assert config.output == Path.join(dir, "out.sarif")
    refute config.check_retired
  end

  test "invalid flags and values produce errors", %{dir: dir} do
    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir, "--unknown-flag"])
    assert msg =~ "invalid option"

    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir, "--fail-on", "maybe"])
    assert msg =~ "--fail-on"

    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir, "--format", "xml"])
    assert msg =~ "--format"

    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir, "--otp-version", "x"])
    assert msg =~ "--otp-version"

    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir, "positional"])
    assert msg =~ "unexpected argument"

    assert {:error, msg} = Config.from_cli_and_file(["--project-dir", Path.join(dir, "missing")])
    assert msg =~ "does not exist"
  end

  test "positional arguments are kept when allowed", %{dir: dir} do
    assert {:ok, config} =
             Config.from_cli_and_file(["CVE-2026-1", "--project-dir", dir], allow_args: true)

    assert config.args == ["CVE-2026-1"]
  end

  test "an explicit --config path must exist", %{dir: dir} do
    assert {:error, msg} =
             Config.from_cli_and_file(["--project-dir", dir, "--config", "nope.exs"], cwd: dir)

    assert msg =~ "configuration file not found"
  end

  test "severity ranks are ordered and unknown is fail-safe" do
    assert Config.severity_rank(:low) < Config.severity_rank(:medium)
    assert Config.severity_rank(:high) < Config.severity_rank(:critical)
    assert Config.severity_rank(:unknown) == Config.severity_rank(:critical)
  end
end
