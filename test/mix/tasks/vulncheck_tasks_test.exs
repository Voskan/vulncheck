defmodule Mix.Tasks.VulncheckTasksTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias VulnCheck.Test.{Project, Tmp}

  defp offline(root, cache),
    do: ["--project-dir", root, "--cache-dir", cache, "--offline", "--no-color", "--no-retired"]

  describe "mix vulncheck" do
    test "exits with the scan's exit code" do
      root = Project.shop!()
      cache = Project.cache!()

      output =
        capture_io(fn ->
          assert catch_exit(Mix.Tasks.Vulncheck.run(offline(root, cache))) == {:shutdown, 1}
        end)

      assert output =~ "[REACHABLE] CVE-2026-54892"

      output =
        capture_io(fn ->
          assert Mix.Tasks.Vulncheck.run(offline(root, cache) ++ ["--fail-on", "none"]) == :ok
        end)

      assert output =~ "Summary: 1 reachable"

      capture_io(:stderr, fn ->
        assert catch_exit(Mix.Tasks.Vulncheck.run(["--bogus"])) == {:shutdown, 2}
      end)
    end

    test "warns when the target environment was not compiled" do
      root = Project.shop!(deps: [{"jason", "1.4.4"}], compile: false)

      output =
        capture_io(fn -> assert Mix.Tasks.Vulncheck.run(offline(root, Project.cache!())) == :ok end)

      assert output =~ "no compiled build found under _build/"

      json_output =
        capture_io(fn ->
          assert Mix.Tasks.Vulncheck.run(
                   offline(root, Project.cache!()) ++ ["--format", "json", "--quiet"]
                 ) == :ok
        end)

      assert %{
               "schema_version" => "1.0.0",
               "warnings" => ["no compiled build found under _build/" <> _]
             } = JSON.decode!(json_output)
    end
  end

  test "mix vulncheck.init writes .vulncheck.exs once" do
    root = Project.shop!(deps: [{"jason", "1.4.4"}], compile: false)

    assert capture_io(fn -> assert Mix.Tasks.Vulncheck.Init.run(["--project-dir", root]) == :ok end) =~
             "Wrote"

    assert File.regular?(Path.join(root, ".vulncheck.exs"))

    assert capture_io(:stderr, fn ->
             assert catch_exit(Mix.Tasks.Vulncheck.Init.run(["--project-dir", root])) ==
                      {:shutdown, 2}
           end) =~ "--force"
  end

  test "mix vulncheck.explain prints the advisory and local status" do
    root = Project.shop!()

    output =
      capture_io(fn ->
        assert Mix.Tasks.Vulncheck.Explain.run([
                 "EEF-CVE-2026-101028" | offline(root, Project.cache!())
               ]) == :ok
      end)

    assert output =~ "CVE-2026-101028 — Ash.count, Ash.exists and Ash.aggregate"
    assert output =~ "Routines:  Ash.Actions.Aggregate.run/4"
    assert output =~ "Verdict:   UNREACHABLE"
  end

  test "mix vulncheck.feeds status and bundle" do
    cache = Project.cache!()
    out = Path.join(Tmp.mkdir!("task-bundle"), "feeds.tar.gz")

    assert capture_io(fn ->
             assert Mix.Tasks.Vulncheck.Feeds.run(["status", "--cache-dir", cache]) == :ok
           end) =~
             "OSV Hex archive: 2 advisories"

    assert capture_io(fn ->
             assert Mix.Tasks.Vulncheck.Feeds.run(["bundle", "-o", out, "--cache-dir", cache]) ==
                      :ok
           end) =~
             "Wrote #{out}"

    assert {:ok, files} = :erl_tar.extract(String.to_charlist(out), [:compressed, :memory])
    assert Enum.any?(files, fn {name, _} -> name == ~c"manifest.json" end)
  end

  test "every task is documented" do
    for task <- [
          Mix.Tasks.Vulncheck,
          Mix.Tasks.Vulncheck.Init,
          Mix.Tasks.Vulncheck.Explain,
          Mix.Tasks.Vulncheck.Feeds
        ] do
      assert Mix.Task.shortdoc(task) =~ ~r/\w/
      assert {:docs_v1, _, _, _, %{"en" => doc}, _, _} = Code.fetch_docs(task)
      assert doc =~ "mix vulncheck"
    end
  end
end
