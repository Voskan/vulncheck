defmodule VulnCheck.Cache.BeamCodecTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Cache.BeamCodec
  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary}

  defp full_summary do
    mfa_a = %MFA{module: "Elixir.Demo", function: "run", arity: 1}
    mfa_b = %MFA{module: "Elixir.Helper", function: "go", arity: 2}

    %ModuleSummary{
      module: "Elixir.Demo",
      source_file: "lib/demo.ex",
      sha256: "abc123",
      package: "demo",
      has_debug_info: true,
      functions: [{"run", 1}],
      function_lines: %{{"run", 1} => 10},
      exports: [{"run", 1}],
      behaviours: ["Elixir.GenServer"],
      attributes: %{"vsn" => [1]},
      edges: [%CallEdge{from: mfa_a, to: mfa_b, file: "lib/demo.ex", line: 12, kind: :static_call}],
      dynamic_dispatches: [
        %DynamicCall{
          caller: mfa_a,
          known_module: "Elixir.Helper",
          known_function: nil,
          arity: 2,
          min_arity: 1,
          file: "lib/demo.ex",
          line: 14,
          kind: :module_function
        }
      ],
      module_refs: [{mfa_a, "Elixir.Helper", "lib/demo.ex", 15}],
      mfa_refs: [
        %CallEdge{from: mfa_a, to: mfa_b, file: "lib/demo.ex", line: 16, kind: :static_call}
      ],
      init_literals: [{mfa_a, mfa_b, [{:atom, "ok"}], "lib/demo.ex", 17}],
      imports: [{"Elixir.Helper", "go", 2}]
    }
  end

  test "pack/1 and unpack/3 round-trip full summaries and share strings via pool" do
    summary = full_summary()
    {strings, packed} = BeamCodec.pack(summary)
    assert BeamCodec.valid?(strings, packed)

    {unpacked1, pool1} = BeamCodec.unpack(strings, packed)
    assert unpacked1 == summary

    {unpacked2, pool2} = BeamCodec.unpack(strings, packed, pool1)
    assert unpacked2 == summary
    assert map_size(pool2) == map_size(pool1)
  end

  test "valid?/2 rejects corrupt strings, tuple sizes, out-of-range indices and bad field types" do
    {strings, packed} = BeamCodec.pack(full_summary())
    n = tuple_size(strings)

    refute BeamCodec.valid?(:not_a_tuple, packed)
    refute BeamCodec.valid?(strings, :not_a_tuple)
    refute BeamCodec.valid?(strings, {0, 1})
    refute BeamCodec.valid?({123}, packed)
    refute BeamCodec.valid?(put_elem(strings, 0, ""), packed)

    # Out-of-range module index
    refute BeamCodec.valid?(strings, put_elem(packed, 0, n))
    # Bad has_debug_info
    refute BeamCodec.valid?(strings, put_elem(packed, 4, :yes))
    # Bad functions list
    refute BeamCodec.valid?(strings, put_elem(packed, 5, [{n, 1}]))
    refute BeamCodec.valid?(strings, put_elem(packed, 5, :bad))
    # Bad function_lines
    refute BeamCodec.valid?(strings, put_elem(packed, 6, %{{0, 1} => 0}))
    refute BeamCodec.valid?(strings, put_elem(packed, 6, :bad))
    # Bad behaviours
    refute BeamCodec.valid?(strings, put_elem(packed, 8, [n]))
    refute BeamCodec.valid?(strings, put_elem(packed, 8, :bad))
    # Bad edges (unknown kind, non-list)
    bad_edge = {{0, 0, 1}, {0, 0, 1}, nil, 1, :unknown_kind}
    refute BeamCodec.valid?(strings, put_elem(packed, 10, [bad_edge]))
    refute BeamCodec.valid?(strings, put_elem(packed, 10, :bad))
    # Bad dynamic_dispatches
    bad_dyn = {{0, 0, 1}, nil, nil, nil, 0, nil, 1, :bad_kind}
    refute BeamCodec.valid?(strings, put_elem(packed, 11, [bad_dyn]))
    refute BeamCodec.valid?(strings, put_elem(packed, 11, :bad))
    # Bad module_refs
    refute BeamCodec.valid?(strings, put_elem(packed, 12, [{:bad}]))
    refute BeamCodec.valid?(strings, put_elem(packed, 12, :bad))
    # Bad init_literals
    refute BeamCodec.valid?(strings, put_elem(packed, 14, [{:bad}]))
    refute BeamCodec.valid?(strings, put_elem(packed, 14, :bad))
    # Bad imports
    refute BeamCodec.valid?(strings, put_elem(packed, 15, [{n, 0, 1}]))
    refute BeamCodec.valid?(strings, put_elem(packed, 15, :bad))
  end
end
