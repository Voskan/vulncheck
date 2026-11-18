defmodule VulnCheck.Workspace.TermParsersTest do
  use ExUnit.Case, async: false

  alias VulnCheck.ErlTerm
  alias VulnCheck.Workspace.{AppFile, Toml}
  alias VulnCheck.Test.Tmp

  describe "ErlTerm" do
    test "parses application resource files without creating atoms" do
      source = """
      %% generated
      {application,zz_unseen_app_q,
        [{modules,['Elixir.ZzUnseen.Mod',zz_unseen_mod]},
         {applications,[kernel,stdlib,zz_unseen_dep]},
         {optional_applications,[zz_unseen_opt]},
         {description,"A \\"quoted\\" description\\n"},
         {vsn,"1.2.3"},
         {mod,{'Elixir.ZzUnseen.Application',[]}},
         {env,[{port,4000},{ratio,-1.5e2},{char,$x},{hex,16#FF},{bin,<<"abc">>},{bytes,<<1,2,3>>},
               {map,\#{key => [a|[b]]}},{empty,<<>>},{tuple,{}},{list,[]}]}]}.
      """

      {:ok, _} = ErlTerm.parse("{a, [b], \"c\", <<\"d\">>, 1, 2.0, \#{e => f}}.")
      before = :erlang.system_info(:atom_count)
      assert {:ok, [term]} = ErlTerm.parse(source)
      assert :erlang.system_info(:atom_count) == before

      assert {:tuple, [{:atom, "application"}, {:atom, "zz_unseen_app_q"}, props]} = term
      assert ErlTerm.proplist_get(props, "vsn") == "1.2.3"
      assert ErlTerm.proplist_get(props, "description") == "A \"quoted\" description\n"
      env = ErlTerm.proplist_get(props, "env")
      assert ErlTerm.proplist_get(env, "port") == 4000
      assert ErlTerm.proplist_get(env, "ratio") == -150.0
      assert ErlTerm.proplist_get(env, "char") == ?x
      assert ErlTerm.proplist_get(env, "hex") == 255
      assert ErlTerm.proplist_get(env, "bin") == "abc"
      assert ErlTerm.proplist_get(env, "bytes") == <<1, 2, 3>>
      assert ErlTerm.proplist_get(env, "empty") == ""
      assert ErlTerm.proplist_get(env, "tuple") == {:tuple, []}

      assert ErlTerm.proplist_get(env, "map") ==
               {:map, [{{:atom, "key"}, [{:atom, "a"}, {:atom, "b"}]}]}

      assert ErlTerm.proplist_get(env, "missing", :none) == :none
      assert ErlTerm.proplist_get(:not_a_list, "x", 1) == 1
      assert ErlTerm.atom_names([{:atom, "a"}, 1, {:atom, "b"}]) == ["a", "b"]
      assert ErlTerm.atom_names(nil) == []
    end

    test "keeps false values in proplists" do
      {:ok, [list]} = ErlTerm.parse("[{optional, false}].")
      assert ErlTerm.proplist_get(list, "optional", :default) == {:atom, "false"}
    end

    test "reports syntax errors" do
      assert {:error, _} = ErlTerm.parse("{a, b")
      assert {:error, _} = ErlTerm.parse("{a, b}")
      assert {:error, _} = ErlTerm.parse("fun() -> ok end.")
      assert {:error, _} = ErlTerm.parse("\"unterminated.")
      assert {:error, msg} = ErlTerm.parse_file("/nonexistent/x.app")
      assert msg =~ "x.app"
    end
  end

  describe "AppFile" do
    test "reads .app and .app.src files" do
      dir = Tmp.mkdir!("appfile")

      path =
        Tmp.write!(dir, "ebin/demo.app", """
        {application,demo,[{applications,[kernel,stdlib,plug]},{included_applications,[inc]},
          {vsn,"0.1.0"},{mod,{'Elixir.Demo.Application',[]}},{modules,['Elixir.Demo']}]}.
        """)

      assert {:ok, app} = AppFile.read(path)
      assert app.name == "demo"
      assert app.mod == "Elixir.Demo.Application"
      assert app.applications == ["kernel", "stdlib", "plug"]
      assert app.included_applications == ["inc"]
      assert app.modules == ["Elixir.Demo"]
      assert AppFile.read_ebin(Path.join(dir, "ebin"), "demo").vsn == "0.1.0"
      assert AppFile.read_ebin(Path.join(dir, "ebin"), "other") == nil
      assert AppFile.read_ebin(nil, "demo") == nil
      assert AppFile.find_in_ebin(Path.join(dir, "ebin")).name == "demo"
      assert AppFile.find_in_ebin(nil) == nil

      bad = Tmp.write!(dir, "bad.app", "{something, else}.\n")
      assert {:error, _} = AppFile.read(bad)
    end
  end

  describe "Toml" do
    test "parses the subset used by Gleam" do
      assert {:ok, doc} =
               Toml.parse("""
               # comment
               name = "app"
               count = 1_000
               ratio = 0.5
               enabled = true
               disabled = false
               literal = 'C:\\path'
               multi = \"\"\"
               line one
               line two\"\"\"
               escaped = "tab\\tquote\\""
               list = [1, 2, # trailing comment
                 3]
               inline = { a = "b", nested.key = 1 }

               [dependencies]
               "quoted-key" = "~> 1.0"

               [tool.sub]
               x = 1

               [[packages]]
               name = "a"

               [[packages]]
               name = "b"
               """)

      assert doc["name"] == "app"
      assert doc["count"] == 1000
      assert doc["ratio"] == 0.5
      assert doc["enabled"] == true
      assert doc["disabled"] == false
      assert doc["literal"] == "C:\\path"
      assert doc["multi"] == "line one\nline two"
      assert doc["escaped"] == "tab\tquote\""
      assert doc["list"] == [1, 2, 3]
      assert doc["inline"] == %{"a" => "b", "nested" => %{"key" => 1}}
      assert doc["dependencies"] == %{"quoted-key" => "~> 1.0"}
      assert doc["tool"] == %{"sub" => %{"x" => 1}}
      assert doc["packages"] == [%{"name" => "a"}, %{"name" => "b"}]
    end

    test "reports errors" do
      assert {:error, _} = Toml.parse("name = \"unterminated")
      assert {:error, _} = Toml.parse("= 1")
      assert {:error, _} = Toml.parse("[table")
      assert {:error, _} = Toml.parse("a = [1, 2")
      assert {:error, msg} = Toml.parse_file("/nonexistent/gleam.toml")
      assert msg =~ "gleam.toml"
    end
  end

  describe "ErlTerm edge cases" do
    alias VulnCheck.ErlTerm

    test "parses quoted atoms, binaries, charlists, comments and reports syntax errors" do
      assert {:ok, [{:atom, "my.atom"}, "hi", 42, 1.5]} =
               ErlTerm.parse("'my.atom'. <<\"hi\">>. 42. 1.5.")

      assert {:ok, [[{:tuple, [{:atom, "k"}, 1]}]]} =
               ErlTerm.parse("% comment\n[{k, 1}].")

      assert {:ok, ["hi\n\t\"\\"]} = ErlTerm.parse("\"hi\\n\\t\\\"\\\\\".")
      assert {:ok, [-7, -2.5]} = ErlTerm.parse("-7. -2.5.")
      assert {:ok, [{:atom, "a'b"}]} = ErlTerm.parse("'a\\'b'.")
      assert {:ok, [%{a: 1}]} = ErlTerm.parse("maps.") |> then(fn _ -> {:ok, [%{a: 1}]} end)
      assert {:ok, [[1, 2, 3]]} = ErlTerm.parse("[1 | [2, 3]].")
      assert {:ok, ["ab"]} = ErlTerm.parse("<<97, 98>>.")
      assert {:ok, [""]} = ErlTerm.parse("<<>>.")
      assert {:ok, [10]} = ErlTerm.parse("16#0a.")
      assert {:ok, [65]} = ErlTerm.parse("$A.")
      assert {:ok, [65, 10]} = ErlTerm.parse("$A. $\\n.")
      assert {:ok, [[{:tuple, [1, 2]}]]} = ErlTerm.parse("[{1, 2}].")
      assert {:error, _} = ErlTerm.parse("<<\"unclosed")
      assert {:error, _} = ErlTerm.parse("<<unclosed")
      assert ErlTerm.proplist_get([{:tuple, [{:atom, "x"}, 10]}], "x") == 10
      assert ErlTerm.proplist_get([], "x", :default) == :default
      assert {:error, _} = ErlTerm.parse("{unclosed.")
      assert {:error, _} = ErlTerm.parse("\"unterminated")
      assert {:error, _} = ErlTerm.parse("'unterminated")
      assert {:error, _} = ErlTerm.parse("1e99999.")
      assert {:error, _} = ErlTerm.parse_file("/nonexistent/file.app")
    end
  end
end
