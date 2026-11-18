# Expected verdicts and pre-graph package baselines for the real-world validation corpus.
%{
  verdicts: [
    # (a) Phoenix API on Bandit with Plug.Parsers [:json]
    {"phoenix_bandit", "EEF-CVE-2026-54892", :reachable, :call_chain_proven},
    # (b) Plug + Cowboy with multipart
    {"plug_cowboy_multipart", "EEF-CVE-2026-54892", :reachable, :call_chain_proven},
    # (c) Tesla + Mint with transitive unused hackney
    {"tesla_mint_hackney", "GHSA-3w5p-5r3w-6r2p", :unreachable, :adapter_not_configured},
    # (d) Umbrella of 3 apps with shared mix.lock
    {"umbrella_three_apps", "EEF-CVE-2026-54892", :reachable, :call_chain_proven},
    # (e) rebar3 project with hackney
    {"rebar3_hackney", "GHSA-3w5p-5r3w-6r2p", :potentially_reachable, :active_network_daemon}
  ],
  packages: [
    {"phoenix_bandit", "plug", "1.15.2"},
    {"phoenix_bandit", "bandit", "1.5.0"},
    {"plug_cowboy_multipart", "plug", "1.15.2"},
    {"plug_cowboy_multipart", "cowboy", "2.12.0"},
    {"tesla_mint_hackney", "tesla", "1.8.0"},
    {"tesla_mint_hackney", "mint", "1.5.2"},
    {"tesla_mint_hackney", "hackney", "1.18.1"},
    {"umbrella_three_apps", "plug", "1.15.2"},
    {"rebar3_hackney", "hackney", "1.18.1"}
  ]
}
