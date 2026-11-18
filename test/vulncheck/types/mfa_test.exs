defmodule VulnCheck.Types.MFATest do
  use ExUnit.Case, async: false

  alias VulnCheck.Types.MFA

  doctest VulnCheck.Types.MFA

  describe "parse_routine/1" do
    test "parses quoted Elixir modules in Erlang notation" do
      assert {:ok, %MFA{module: "Elixir.Plug.Conn.Query", function: "decode", arity: 4}} =
               MFA.parse_routine("'Elixir.Plug.Conn.Query':decode/4")
    end

    test "parses native Erlang modules with and without quotes" do
      assert {:ok, %MFA{module: "hex_http_httpc", function: "http_options", arity: 2}} =
               MFA.parse_routine("hex_http_httpc:http_options/2")

      assert {:ok, %MFA{module: "cow_http_hd", function: "parse", arity: 1}} =
               MFA.parse_routine("'cow_http_hd':parse/1")

      assert {:ok, %MFA{module: "cow_http_hd", function: "parse", arity: 1}} =
               MFA.parse_routine(":cow_http_hd.parse/1")
    end

    test "parses idiomatic Elixir notation" do
      assert {:ok, %MFA{module: "Elixir.Ash.Actions.Aggregate", function: "run", arity: 4}} =
               MFA.parse_routine("Ash.Actions.Aggregate.run/4")

      assert {:ok, %MFA{function: "valid_state_and_csrf_token?", arity: 2}} =
               MFA.parse_routine("`Plug.CSRFProtection.valid_state_and_csrf_token?/2`")
    end

    test "parses quoted function names" do
      assert {:ok, %MFA{module: "Elixir.Jason", function: "decode!", arity: 1}} =
               MFA.parse_routine("'Elixir.Jason':'decode!'/1")
    end

    test "rejects routines without an explicit arity or with garbage" do
      assert MFA.parse_routine("Ash.read") == :error
      assert MFA.parse_routine("'Elixir.Ash':read") == :error
      assert MFA.parse_routine("Ash.read/x") == :error
      assert MFA.parse_routine("/2") == :error
      assert MFA.parse_routine("") == :error
      assert MFA.parse_routine("Mod.fun/999") == :error
      assert MFA.parse_routine("a b c/1") == :error
      assert MFA.parse_routine(nil) == :error
    end

    test "does not create atoms for unseen module names" do
      names =
        for i <- 1..1000 do
          "'Elixir.Zz#{i}Gen#{System.unique_integer([:positive])}.Mod':fn_#{i}_x/#{rem(i, 5)}"
        end

      before = :erlang.system_info(:atom_count)

      parsed =
        Enum.map(names, fn name ->
          {:ok, mfa} = MFA.parse_routine(name)
          MFA.format(mfa)
        end)

      assert :erlang.system_info(:atom_count) == before
      assert length(parsed) == 1000
    end
  end

  describe "normalize_module/1" do
    test "handles atoms, aliases and Erlang names" do
      assert MFA.normalize_module(:cowlib) == "cowlib"
      assert MFA.normalize_module(Plug.Conn) == "Elixir.Plug.Conn"
      assert MFA.normalize_module("Plug.Conn.Query") == "Elixir.Plug.Conn.Query"
      assert MFA.normalize_module("'Elixir.Plug.Conn.Query'") == "Elixir.Plug.Conn.Query"
      assert MFA.normalize_module(":cow_http2_machine") == "cow_http2_machine"
      assert MFA.normalize_module("'cow_http2_machine'") == "cow_http2_machine"
      assert MFA.normalize_module("cow_http2_machine") == "cow_http2_machine"
    end
  end

  describe "format/1" do
    test "formats Elixir and Erlang routines for humans" do
      assert MFA.format(MFA.new("Elixir.Plug.Conn.Query", "decode", 4)) ==
               "Plug.Conn.Query.decode/4"

      assert MFA.format(MFA.new("cow_http_hd", "parse", 1)) == ":cow_http_hd.parse/1"
      assert MFA.format(MFA.new(:lists, :map, 2)) == ":lists.map/2"
    end
  end

  test "compare/2 and to_tuple/1 are deterministic" do
    a = MFA.new("Elixir.A", "x", 1)
    b = MFA.new("Elixir.B", "x", 1)
    assert MFA.compare(a, b) == :lt
    assert MFA.compare(b, a) == :gt
    assert MFA.compare(a, a) == :eq
    assert MFA.to_tuple(a) == {"Elixir.A", "x", 1}
    assert MFA.elixir_module?("Elixir.A")
    refute MFA.elixir_module?("cowlib")
  end
end
