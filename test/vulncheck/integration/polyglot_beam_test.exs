defmodule VulnCheck.Integration.PolyglotBeamTest do
  # Erlang (rebar3) and Gleam workspaces built from native .erl sources in
  # their own build layouts, scanned offline against the advisory corpus.
  use ExUnit.Case, async: true

  import VulnCheck.Test.FixtureBuilder

  alias VulnCheck.Types.MFA

  @jsx %{
    name: "jsx",
    version: "3.1.0",
    erl: [
      {"src/jsx.erl",
       """
       -module(jsx).
       -export([decode/1, encode/1]).

       decode(Json) ->
           jsx_decoder:decode(Json, []).

       encode(Term) -> Term.
       """},
      {"src/jsx_decoder.erl",
       """
       -module(jsx_decoder).
       -export([decode/2]).

       decode(Json, Config) -> {Json, Config}.
       """}
    ]
  }

  test "rebar3: an Erlang application reaching jsx_decoder through jsx:decode/1" do
    root =
      rebar_project!("edge",
        mod: "edge_app",
        applications: [:jsx],
        packages: [@jsx],
        erl: [
          {"src/edge_app.erl",
           """
           -module(edge_app).
           -behaviour(application).
           -export([start/2, stop/1]).

           start(_Type, _Args) ->
               edge_api:parse(<<"{}">>).

           stop(_State) -> ok.
           """},
          {"src/edge_api.erl",
           """
           -module(edge_api).
           -export([parse/1]).

           parse(Body) ->
               jsx:decode(Body).
           """}
        ]
      )

    report = scan!(root)
    assert report.workspace.project_type == :rebar3
    assert report.workspace.build_env == "default"

    finding = finding!(report, "EEF-CVE-2026-60107")
    assert finding.verdict == :reachable
    assert finding.reason == :call_chain_proven
    assert finding.target_mfa == MFA.new("jsx_decoder", "decode", 2)

    assert Enum.map(finding.trace, &{MFA.format(&1.mfa), &1.file, &1.line}) == [
             {":edge_app.start/2", "src/edge_app.erl", 6},
             {":edge_api.parse/1", "src/edge_api.erl", 5},
             {":jsx.decode/1", "_build/default/lib/jsx/src/jsx.erl", 5},
             {":jsx_decoder.decode/2", "_build/default/lib/jsx/src/jsx_decoder.erl", 4}
           ]
  end

  test "rebar3: an unused dependency function stays unreachable" do
    root =
      rebar_project!("edge",
        mod: "edge_app",
        applications: [:jsx],
        packages: [@jsx],
        erl: [
          {"src/edge_app.erl",
           """
           -module(edge_app).
           -export([start/2]).

           start(_Type, _Args) -> jsx:encode(ok).
           """}
        ]
      )

    finding = root |> scan!() |> finding!("EEF-CVE-2026-60107")
    assert finding.verdict == :unreachable
    assert finding.reason == :function_not_called
  end

  test "gleam: compiled modules in build/dev/erlang reach thoas_decode" do
    thoas = %{
      name: "thoas",
      version: "1.2.1",
      erl: [
        {"src/thoas.erl",
         ~S"""
         -module(thoas).
         -export([decode/1]).

         decode(Json) -> thoas_decode:decode(Json, #{}).
         """},
        {"src/thoas_decode.erl",
         ~S"""
         -module(thoas_decode).
         -export([decode/2]).

         decode(Json, Opts) -> {ok, {Json, Opts}}.
         """}
      ]
    }

    root =
      gleam_project!("storefront",
        applications: [:thoas],
        packages: [thoas],
        erl: [
          {"storefront@json.erl",
           """
           -module('storefront@json').
           -export([parse/1]).

           parse(Body) ->
               thoas:decode(Body).
           """},
          {"storefront.erl",
           """
           -module(storefront).
           -export([main/0]).

           main() -> 'storefront@json':parse(<<"[]">>).
           """}
        ]
      )

    report = scan!(root)
    assert report.workspace.project_type == :gleam
    assert report.workspace.project_name == "storefront"

    finding = finding!(report, "EEF-CVE-2026-60108")
    assert finding.verdict == :reachable
    assert finding.reason == :call_chain_proven

    # no application callback: every export is a root, so the chain starts
    # at the closest one
    assert Enum.map(finding.trace, &MFA.format(&1.mfa)) == [
             ":storefront@json.parse/1",
             ":thoas.decode/1",
             ":thoas_decode.decode/2"
           ]

    assert Enum.find(finding.trace, &(&1.mfa.module == "storefront@json")).file ==
             "build/dev/erlang/storefront/_gleam_artefacts/storefront@json.erl"
  end
end
