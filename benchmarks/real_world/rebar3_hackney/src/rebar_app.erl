-module(rebar_app).
-export([fetch/1]).

fetch(Url) ->
    hackney:get(Url).
