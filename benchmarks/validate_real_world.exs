# Opt-in real-world validation harness.
#
#     MIX_ENV=prod mix escript.build
#     mix run benchmarks/validate_real_world.exs --offline --bundle /tmp/bundle.tar.gz
#     mix run benchmarks/validate_real_world.exs --markdown
#
Code.require_file("validation_comparator.exs", __DIR__)

defmodule VulnCheck.Bench.RealWorld do
  alias VulnCheck.Bench.ValidationComparator

  @projects [
    {"phoenix_bandit", "mix.lock", :mix},
    {"plug_cowboy_multipart", "mix.lock", :mix},
    {"tesla_mint_hackney", "mix.lock", :mix},
    {"umbrella_three_apps", "mix.lock", :mix},
    {"rebar3_hackney", "rebar.lock", :rebar3}
  ]

  def main(argv) do
    {opts, _args, _invalid} =
      OptionParser.parse(argv,
        strict: [
          keep: :boolean,
          markdown: :boolean,
          offline: :boolean,
          bundle: :string,
          escript: :string,
          allow_skip: :boolean
        ]
      )

    escript = Keyword.get(opts, :escript, Path.expand("../vulncheck", __DIR__))

    unless File.regular?(escript) do
      Mix.raise("escript not found at #{escript}; run `MIX_ENV=prod mix escript.build` first")
    end

    {expected, _} = Code.eval_file(Path.expand("real_world_expected.exs", __DIR__))
    fixtures_dir = Path.expand("real_world", __DIR__)

    root =
      Path.join(
        System.tmp_dir!(),
        "vulncheck-realworld-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)

    passed? =
      try do
        results =
          Enum.map(@projects, fn {name, lock_file, kind} ->
            run_project(name, lock_file, kind, fixtures_dir, root, escript, expected, opts)
          end)

        summary = ValidationComparator.summarize(results, expected.verdicts)

        if Keyword.get(opts, :markdown, false) do
          IO.puts(ValidationComparator.to_markdown(summary))
        else
          Enum.each(summary.projects, &print_text_row/1)
        end

        summary.passed?
      after
        unless Keyword.get(opts, :keep, false), do: File.rm_rf!(root)
      end

    unless passed?, do: System.halt(1)
  end

  defp run_project(name, lock_file, kind, fixtures_dir, root, escript, expected, opts) do
    src = Path.join(fixtures_dir, name)
    dir = Path.join(root, name)
    File.cp_r!(src, dir)
    lock_sha256 = sha256_file(Path.join(dir, lock_file))

    with {:ok, build_cmd} <- build_command(kind),
         :ok <- run_build(name, dir, build_cmd),
         {:ok, report} <- scan(escript, dir, opts) do
      result = ValidationComparator.compare(name, report, expected.verdicts, expected.packages)
      Map.merge(result, %{lock_sha256: lock_sha256, feed: report["feed"], tool: report["tool"]})
    else
      {:skip, reason} ->
        if Keyword.get(opts, :allow_skip, false) do
          %{
            ValidationComparator.failed_project(name, reason, expected.verdicts)
            | status: :skipped,
              passed?: true
          }
        else
          ValidationComparator.failed_project(name, reason, expected.verdicts)
        end

      {:error, reason} ->
        ValidationComparator.failed_project(name, reason, expected.verdicts)
    end
  end

  defp build_command(:mix),
    do: {:ok, {"sh", ["-c", "mix deps.get && MIX_ENV=prod mix compile"]}}

  defp build_command(:rebar3) do
    case find_rebar3() do
      nil -> {:skip, "rebar3 executable not found"}
      bin -> {:ok, {bin, ["as", "prod", "compile"]}}
    end
  end

  defp find_rebar3 do
    System.find_executable("rebar3") ||
      Path.expand("~/.mix/elixir/*/rebar3") |> Path.wildcard() |> List.first()
  end

  defp run_build(name, dir, {cmd, args}) do
    {out, code} = System.cmd(cmd, args, cd: dir, stderr_to_stdout: true)

    if code == 0 do
      :ok
    else
      {:error, "build failed for #{name} (exit #{code}): #{String.slice(out, 0, 400)}"}
    end
  end

  defp scan(escript, dir, opts) do
    args =
      ["--project-dir", dir, "--format", "json", "--quiet"] ++
        if(Keyword.get(opts, :offline, false), do: ["--offline"], else: []) ++
        if(bundle = Keyword.get(opts, :bundle), do: ["--bundle", bundle], else: [])

    {out, code} = System.cmd(escript, args)

    if code in [0, 1] do
      case JSON.decode(out) do
        {:ok, %{} = report} -> {:ok, report}
        {:error, err} -> {:error, "invalid JSON from escript: #{inspect(err)}"}
      end
    else
      {:error, "escript failed with exit #{code}: #{String.trim(out)}"}
    end
  end

  defp print_text_row(%{status: :error} = r) do
    IO.puts("#{r.project}: ERROR (#{r.error})")
  end

  defp print_text_row(r) do
    IO.puts(
      "#{r.project}: matched=#{r.matched}/#{r.total_expected} unexpected=#{length(r.unexpected)} " <>
        "precision=#{r.precision_percent}% recall=#{r.recall_percent}% " <>
        "noise_reduction=#{r.noise_reduction_percent}% lock_sha256=#{r[:lock_sha256]}"
    )
  end

  defp sha256_file(path) do
    if File.regular?(path) do
      :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
    else
      "missing"
    end
  end
end

VulnCheck.Bench.RealWorld.main(System.argv())
