defmodule VulnCheck.Types.TypesTest do
  use ExUnit.Case, async: false

  alias VulnCheck.Literal
  alias VulnCheck.Types.{Advisory, Finding, MFA, Package, Summary, Workspace}

  doctest VulnCheck.Types.Advisory

  test "advisory helpers" do
    adv = %Advisory{id: "GHSA-1", package: "plug", aliases: ["CVE-2026-54892"]}
    assert Advisory.cve_id(adv) == "CVE-2026-54892"
    assert Advisory.identifiers(adv) == ["GHSA-1", "CVE-2026-54892"]
    assert Advisory.cve_id(%Advisory{id: "GHSA-2", package: "x"}) == nil
    assert Advisory.parse_severity("MODERATE") == :medium
    assert Advisory.parse_severity("Critical") == :critical
    assert Advisory.parse_severity("weird") == :unknown
    assert Advisory.parse_severity(nil) == :unknown
    assert Advisory.severity_from_score(7.5) == :high
    assert Advisory.severity_from_score(5.0) == :medium
    assert Advisory.severity_from_score(0.1) == :low
    assert Advisory.severity_from_score(0.0) == :unknown
    assert hd(Advisory.severities()) == :critical
  end

  test "finding fingerprints are stable and sensitive to verdict" do
    mfa = MFA.new("Elixir.Ash.Actions.Aggregate", "run", 4)
    a = Finding.fingerprint("EEF-CVE-2026-101028", "ash", :reachable, mfa)
    b = Finding.fingerprint("EEF-CVE-2026-101028", "ash", :reachable, mfa)
    c = Finding.fingerprint("EEF-CVE-2026-101028", "ash", :unreachable, nil)
    assert a == b
    assert a != c
    assert String.length(a) == 64

    finding = %Finding{
      advisory_id: "EEF-CVE-2026-101028",
      package: "ash",
      installed_version: "3.34.2",
      severity: :high,
      verdict: :reachable,
      reason: :call_chain_proven
    }

    assert Finding.cve_id(finding) == "CVE-2026-101028"
    assert Finding.active?(finding)
    assert length(Finding.reasons()) == 13
    assert Finding.verdicts() == [:reachable, :potentially_reachable, :retired, :unreachable]
  end

  test "summary counters and noise reduction" do
    base = %Finding{
      advisory_id: "A",
      package: "p",
      installed_version: "1.0.0",
      severity: :low,
      verdict: :unreachable,
      reason: :module_not_loaded
    }

    findings = [
      %{base | verdict: :reachable, reason: :call_chain_proven},
      %{base | verdict: :potentially_reachable, reason: :missing_symbol_granularity},
      base,
      base,
      %{base | verdict: :retired, reason: :package_retired},
      %{base | suppressed: true, verdict: :reachable},
      %{base | suppression_expired: true, verdict: :reachable}
    ]

    summary = Summary.from_findings(findings)
    assert summary.reachable == 2
    assert summary.potentially_reachable == 1
    assert summary.unreachable == 2
    assert summary.retired == 1
    assert summary.suppressed == 1
    assert summary.expired_suppressions == 1
    assert summary.total == 7
    assert Summary.noise_reduction(summary) == 33
    assert Summary.noise_reduction(%Summary{}) == 0
  end

  test "workspace package scope helpers" do
    ws = %Workspace{
      root_dir: "/tmp/x",
      project_name: "x",
      project_type: :mix,
      env: :prod,
      otp_release: "27",
      packages: %{
        "b" => %Package{name: "b", version: "1.0.0", source: :hex, scope: :prod},
        "a" => %Package{name: "a", version: "1.0.0", source: :hex, scope: :prod},
        "c" => %Package{name: "c", version: "1.0.0", source: :hex, scope: :non_prod}
      }
    }

    assert Enum.map(Workspace.prod_packages(ws), & &1.name) == ["a", "b"]
    assert Enum.map(Workspace.non_prod_packages(ws), & &1.name) == ["c"]
  end

  describe "Literal" do
    test "converts literals without creating atoms" do
      # Warm up lazily loaded parser modules before measuring.
      {:ok, _} =
        Literal.parse(~S|[w: {:w, "s", 1, -2, 3.5, nil, true}, m: %{"k" => [W.X]}, b: <<"a">>]|)

      before = :erlang.system_info(:atom_count)

      assert {:ok, term} =
               Literal.parse(~S"""
               [zz_lit_key_a: {:zz_lit_val_b, "s", 1, -2, 3.5, nil, true},
                map: %{"k" => [ZzLit.Alias.Name]}, bin: <<"ab", "c">>]
               """)

      assert :erlang.system_info(:atom_count) == before

      assert Literal.kw_get(term, "zz_lit_key_a") ==
               {:tuple, [{:atom, "zz_lit_val_b"}, "s", 1, -2, 3.5, nil, true]}

      assert Literal.kw_get(term, "map") == {:map, [{"k", [{:alias, "Elixir.ZzLit.Alias.Name"}]}]}
      assert Literal.kw_get(term, "bin") == "abc"
      assert Literal.kw_get(term, "missing", :default) == :default
      assert Literal.kw_get({:map, [{{:atom, "a"}, 1}]}, "a") == 1
      assert Literal.kw_get("other", "a", 0) == 0
      assert {:ok, [{"zz_lit_key_a", _} | _]} = Literal.keyword_pairs(term)
      assert Literal.keyword_pairs([1]) == :error
      assert Literal.keyword_pairs(:x) == :error
    end

    test "rejects executable code" do
      assert {:error, {:unsafe_expression, 1, code}} = Literal.parse(~S'[a: File.rm_rf!("/")]')
      assert code =~ "File.rm_rf!"
      assert {:error, {:unsafe_expression, _, _}} = Literal.parse("[a: x]")
      assert {:error, {:unsafe_expression, _, _}} = Literal.parse("[a: 1 + 2]")
      assert {:error, {:unsafe_expression, _, _}} = Literal.parse(~S"<<x::8>>")
      assert {:error, msg} = Literal.parse("[a: ")
      assert msg =~ "syntax error"
      assert {:error, {:file_error, _, :enoent}} = Literal.parse_file("/nonexistent/vc.exs")
    end

    test "atom and alias helpers" do
      {:ok, ast} = Literal.quote_string("Foo.Bar")
      assert Literal.alias_name(ast) == "Elixir.Foo.Bar"
      {:ok, ast} = Literal.quote_string(":abc")
      assert Literal.atom?(ast, "abc")
      assert Literal.atom_name(ast) == "abc"
      assert Literal.atom_name(1) == nil
      refute Literal.atom?(1, "abc")
      assert Literal.alias_name(1) == nil
    end
  end
end
