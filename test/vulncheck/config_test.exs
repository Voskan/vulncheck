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

  test "validates numeric, boolean and beam resource limit options in .vulncheck.exs", %{dir: dir} do
    path = Path.join(dir, ".vulncheck.exs")

    File.write!(path, """
    [
      beam_timeout: 5_000,
      max_beam_files: 1_000,
      max_beam_bytes: 1_048_576,
      max_beam_heap_bytes: 16_777_216,
      cache_ttl_seconds: 60,
      max_feed_age_seconds: 3600,
      otp_version: 27
    ]
    """)

    assert {:ok, cfg} = Config.from_cli_and_file(["--project-dir", dir])
    assert cfg.beam_timeout == 5_000
    assert cfg.max_beam_files == 1_000
    assert cfg.otp_version == "27"

    for bad <- [
          "[beam_timeout: 0]",
          "[cache_ttl_seconds: -1]",
          "[max_feed_age_seconds: \"bad\"]",
          "[otp_version: \"invalid\"]",
          "[extra_entrypoints: [{Bad, :fun, -1}]]",
          "[configured_adapters: [unknown_family: SomeMod]]",
          "[unknown_key: 1]",
          "[offline: \"yes\"]",
          "[env: :staging]",
          "[fail_on: :bogus]",
          "[min_severity: :bogus]",
          "[format: :xml]",
          "not_a_keyword_list",
          "["
        ] do
      File.write!(path, bad)
      assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir])
    end

    assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir, "--env", "staging"])
    assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir, "--fail-on", "bogus"])
    assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir, "--min-severity", "bogus"])
    assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir, "--cache-ttl", "-1"])
    assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir, "--max-feed-age", "-1"])

    File.rm!(path)

    assert {:ok, cli_cfg} =
             Config.from_cli_and_file([
               "--project-dir",
               dir,
               "--env",
               "dev",
               "--format",
               "sarif",
               "--sarif",
               "out.sarif",
               "--sbom",
               "sbom.json",
               "--vex",
               "vex.json",
               "--diff",
               "HEAD",
               "--baseline",
               "base.json",
               "--write-baseline",
               "new.json",
               "--forbid-new-suppressions",
               "--show-unreachable",
               "--no-retired",
               "--no-fail-on-retired",
               "--offline",
               "--bundle",
               "bundle.tar.gz",
               "--ignore-file",
               "custom.ignore",
               "--cache-dir",
               "cache",
               "--cache-ttl",
               "120",
               "--max-feed-age",
               "600",
               "--no-color",
               "--quiet",
               "--force"
             ])

    assert cli_cfg.env == :dev
    assert cli_cfg.format == :sarif
    assert cli_cfg.forbid_new_suppressions
    assert cli_cfg.show_unreachable
    refute cli_cfg.check_retired
    refute cli_cfg.fail_on_retired
    assert cli_cfg.offline
    refute cli_cfg.color
    assert cli_cfg.quiet
    assert cli_cfg.force

    assert {:ok, ret_cfg} = Config.from_cli_and_file(["--project-dir", dir, "--retired", "--color"])
    assert ret_cfg.check_retired
    assert ret_cfg.color

    File.write!(path, """
    [
      env: :prod,
      format: :json,
      fail_on: :reachable,
      min_severity: :high,
      output: "out.json",
      sarif: "out.sarif",
      sbom: "out.sbom",
      vex: "out.vex",
      diff: "main",
      baseline: "base.json",
      require_ignore_reason: false,
      require_ignore_expiry: true,
      check_retired: false,
      fail_on_retired: false,
      show_unreachable: true,
      offline: true
    ]
    """)

    assert {:ok, file_cfg} = Config.from_cli_and_file(["--project-dir", dir])
    assert :ok = Config.validate_output_paths(file_cfg)
    assert file_cfg.format == :json
    assert file_cfg.fail_on == :reachable
    assert file_cfg.min_severity == :high
    refute file_cfg.require_ignore_reason
    assert file_cfg.require_ignore_expiry
    refute file_cfg.check_retired
    refute file_cfg.fail_on_retired
    assert file_cfg.show_unreachable
    assert file_cfg.offline

    File.write!(path, """
    [
      otp_version: nil,
      output: nil,
      sarif: nil,
      sbom: nil,
      vex: nil,
      bundle: nil,
      cache_dir: nil,
      diff: nil,
      baseline: nil
    ]
    """)

    assert {:ok, nil_cfg} = Config.from_cli_and_file(["--project-dir", dir])
    assert is_nil(nil_cfg.otp_version)
    assert is_nil(nil_cfg.output)

    for bad_path <- ["[output: \"\"]", "[ignore_file: nil]", "[ignore_file: 123]"] do
      File.write!(path, bad_path)
      assert {:error, _} = Config.from_cli_and_file(["--project-dir", dir])
    end
  end
end
