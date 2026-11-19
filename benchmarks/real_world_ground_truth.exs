# Ground truth for the real-world validation projects, labeled by reading the
# project code and the dependency sources at the pinned lockfile versions.
#
# A label states whether a vulnerable routine of the advisory runs when the
# project runs, independently of the verdict VulnCheck reports:
#
#   * `:called` - the project, its supervision tree or its public API reaches
#     the vulnerable routine with default dependency settings
#   * `:not_called` - no path from the project code, its configuration or the
#     started dependencies leads to the vulnerable routine
#
# Library projects (`tesla_mint_hackney`, `umbrella_three_apps`,
# `rebar3_hackney`) are labeled from their public functions, which callers may
# invoke with any argument. Each entry lists the projects it applies to, the
# advisory, the label and the evidence, with paths relative to `deps/`.
#
# Labels are never derived from VulnCheck output. When a verdict and a label
# disagree, the label stays and the disagreement is reported by the harness.
bandit_servers = ["phoenix_bandit", "bandit_tesla_gateway"]
mint_clients = ["tesla_mint_hackney", "bandit_tesla_gateway"]
json_plugs = ["phoenix_bandit", "bandit_tesla_gateway", "umbrella_three_apps"]
plug_users = json_plugs ++ ["plug_cowboy_multipart"]
unused_hackney = ["tesla_mint_hackney", "bandit_tesla_gateway"]

http2 =
  "Bandit serves HTTP/2 by default (`http_2_options[:enabled]` defaults to true in " <>
    "bandit/lib/bandit.ex) and Bandit.InitialHandler switches to Bandit.HTTP2.Handler on " <>
    "the connection preface, so any client reaches the HTTP/2 stack"

websocket =
  "Bandit.HTTP1.Handler switches to Bandit.WebSocket.Handler only for a " <>
    "`{:upgrade, _, :websocket, _}` result of Bandit.Pipeline, which requires the plug to call " <>
    "Plug.Conn.upgrade_adapter/3; the project's plugs never upgrade"

mint =
  "the Tesla client calls Tesla.Adapter.Mint, which opens Mint.HTTP connections with the " <>
    "default protocols [:http1, :http2] (mint/lib/mint/http.ex), so Mint handles HTTP/1 " <>
    "responses and HTTP/2 when the server negotiates h2"

no_cookies =
  "Plug.Conn.merge_headers/2 calls Plug.Conn.Cookies.encode/2 once per response cookie " <>
    "(plug/lib/plug/conn.ex); the project never calls put_resp_cookie/4 and starts no session " <>
    "plug, so resp_cookies stays empty"

multipart_off =
  "only Plug.Parsers.MULTIPART calls Plug.Conn.read_part_headers/2 and the multipart parse " <>
    "functions, and the project configures no multipart parser"

hackney_unused =
  "hackney is started as an application but the project never issues a hackney request: " <>
    "Tesla uses Tesla.Adapter.Mint, and hackney_manager only serves requests made through :hackney"

%{
  labels: [
    # bandit 1.5.0
    {bandit_servers, "EEF-CVE-2026-105659", :called,
     "#{http2}; Bandit.HTTP2.Connection.handle_frame/3 handles every WINDOW_UPDATE frame"},
    {bandit_servers, "EEF-CVE-2026-108525", :called,
     "#{http2}; Bandit.HTTP2.Connection.handle_frame/3 forwards every DATA frame"},
    {bandit_servers, "EEF-CVE-2026-108529", :called,
     "#{http2}; SETTINGS and WINDOW_UPDATE frames run do_pending_sends/2"},
    {bandit_servers, "EEF-CVE-2026-109584", :called,
     "#{http2}; every HEADERS block is decoded and cookie crumbs are joined"},
    {bandit_servers, "EEF-CVE-2026-110499", :called,
     "#{http2}; the client's SETTINGS_HEADER_TABLE_SIZE resizes the HPACK encoder"},
    {bandit_servers, "EEF-CVE-2026-115269", :called,
     "#{http2}; Plug.Parsers reads JSON request bodies through Bandit.HTTP2.Stream.do_read_data/4"},
    {bandit_servers, "EEF-CVE-2026-116078", :called,
     "#{http2}; request bodies are read through Bandit.HTTP2.Stream.do_read_data/5"},
    {bandit_servers, "EEF-CVE-2026-42788", :called,
     "#{http2}; Bandit.HTTP2.Handler.handle_data/3 calls Bandit.HTTP2.Frame.deserialize/2"},
    {bandit_servers, "EEF-CVE-2026-74836", :called,
     "#{http2}; responses are sent through Bandit.HTTP2.Stream.send_data/3"},
    {bandit_servers, "EEF-CVE-2026-75484", :called,
     "#{http2}; Bandit.HTTP2.Stream.read_headers/1 runs for every request stream"},
    {bandit_servers, "EEF-CVE-2026-105660", :called,
     "Bandit.Pipeline.build_conn!/6 calls determine_host_and_port!/4 for every HTTP/1 request"},
    {bandit_servers, "EEF-CVE-2026-113436", :called,
     "Bandit.Headers.parse_integer/2 parses the Host port and content-length of every request"},
    {bandit_servers, "EEF-CVE-2026-39805", :called,
     "Bandit.HTTP1.Socket.read_headers/1 calls Bandit.Headers.get_content_length/1 for every request"},
    {bandit_servers, "EEF-CVE-2026-39807", :called,
     "Bandit.Pipeline.build_conn!/6 calls determine_scheme/2 for every request"},
    {bandit_servers, "EEF-CVE-2026-39803", :called,
     "Plug.Parsers reads chunked JSON bodies through Bandit.HTTP1.Socket.read_data/2, " <>
       "and Bandit drains unread bodies with the same reader"},
    {bandit_servers, "EEF-CVE-2026-111101", :called,
     "the chunked reader in bandit/lib/bandit/http1/socket.ex runs for chunked request bodies " <>
       "whether or not the route reads the body"},
    {bandit_servers, "EEF-CVE-2026-39804", :not_called,
     "#{websocket}; Bandit.WebSocket.PerMessageDeflate.inflate/2 runs only in a WebSocket connection"},
    {bandit_servers, "EEF-CVE-2026-42786", :not_called,
     "#{websocket}; Bandit.WebSocket.Connection.handle_frame/3 runs only in a WebSocket connection"},
    {bandit_servers, "EEF-CVE-2026-110314", :not_called,
     "#{websocket}; the close handling of Bandit.WebSocket.Connection never runs"},

    # hpax 0.1.2
    {bandit_servers, "EEF-CVE-2026-58226", :called,
     "#{http2}; Bandit.HTTP2.Connection.handle_frame/3 decodes HEADERS with HPAX.decode/2"},
    {["tesla_mint_hackney"], "EEF-CVE-2026-58226", :called,
     "#{mint}; Mint.HTTP2 decodes response headers with HPAX.decode/2"},

    # plug 1.15.2
    {["phoenix_bandit", "bandit_tesla_gateway", "plug_cowboy_multipart"], "EEF-CVE-2026-54892",
     :called,
     "Plug.Parsers.call/2 calls Plug.Conn.fetch_query_params/2, which calls Plug.Conn.Query.decode/4"},
    {["umbrella_three_apps"], "EEF-CVE-2026-54892", :called,
     "Api.handle/1 and Core.parse/1 pass their argument to Plug.Conn.Query.decode/1"},
    {plug_users, "EEF-CVE-2026-56813", :not_called, no_cookies},
    {json_plugs, "EEF-CVE-2026-8468", :not_called, multipart_off},
    {json_plugs, "EEF-CVE-2026-120287", :not_called, multipart_off},
    {json_plugs, "EEF-CVE-2026-56814", :not_called, multipart_off},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-8468", :called,
     "the router configures Plug.Parsers with :multipart, whose parse/5 calls Plug.Conn.read_part_headers/2"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-120287", :called,
     "the router configures Plug.Parsers with :multipart, which runs Plug.Parsers.MULTIPART.parse/5"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-56814", :called,
     "Plug.Parsers.MULTIPART.parse/5 calls parse_multipart/2 for multipart requests"},

    # plug_cowboy 2.7.0, cowboy 2.10.0, cowlib 2.12.1
    {["plug_cowboy_multipart"], "EEF-CVE-2026-32688", :called,
     "cowboy_clear serves [http2, http] by default (cowboy/src/cowboy_clear.erl), and " <>
       "Plug.Cowboy.Conn.conn/1 calls String.to_atom/1 on the scheme of every request"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-65624", :called,
     "cowboy_http parses the headers of every HTTP/1.1 request"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-8466", :not_called,
     "cowboy_req:read_part/3 is never called: Plug parses multipart bodies with its own " <>
       ":plug_multipart module (plug/lib/plug/conn.ex) and plug_cowboy only reads raw body chunks"},
    {["plug_cowboy_multipart"], "GHSA-w4f7-4cxr-rv3c", :not_called,
     "the advisory concerns cow_http_struct_hd:escape_string/2; neither cowboy, plug_cowboy " <>
       "nor the project builds structured-field headers"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-43966", :not_called,
     "no module of cowboy, plug_cowboy or the project calls cow_http_struct_hd"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-43968", :not_called,
     "cow_sse is used only by cowboy_req:stream_events/3, which the project never calls"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-43969", :not_called,
     "cow_cookie:cookie/1 encodes request cookies for HTTP clients; cowboy never calls it"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-43970", :not_called,
     "cow_spdy is not used by cowboy 2.10, which has no SPDY support"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-43971", :not_called,
     "no module of cowboy, plug_cowboy or the project calls cow_link"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-113431", :called,
     "cowboy_http2 decodes every HEADERS block through cow_http2_machine:headers_decode/4, " <>
       "and the clear listener serves HTTP/2 by default"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-59248", :called,
     "cow_http2_machine decodes HEADERS with cow_hpack:decode/3, and the clear listener " <>
       "serves HTTP/2 by default"},
    {["plug_cowboy_multipart"], "EEF-CVE-2026-7790", :called,
     "cowboy_http decodes chunked request bodies with cow_http_te:stream_chunked/2"},

    # mint 1.5.2
    {mint_clients, "EEF-CVE-2026-48861", :called,
     "#{mint}; every request line is built by Mint.HTTP1.Request.encode_request_line/2"},
    {mint_clients, "EEF-CVE-2026-48862", :called,
     "#{mint}; Mint.HTTP2 enables server push and handles PUSH_PROMISE frames"},
    {mint_clients, "EEF-CVE-2026-49753", :called,
     "#{mint}; Mint.HTTP1 parses every content-length response header"},
    {mint_clients, "EEF-CVE-2026-49754", :called,
     "#{mint}; Mint.HTTP2 handles HEADERS and CONTINUATION frames of every response"},
    {mint_clients, "EEF-CVE-2026-59246", :called,
     "#{mint}; Mint.HTTP2.handle_continuation/3 runs for CONTINUATION frames"},
    {mint_clients, "EEF-CVE-2026-91043", :called,
     "#{mint}; Mint.HTTP2.stream/2 decodes and joins response cookie headers"},
    {mint_clients, "EEF-CVE-2026-92103", :called,
     "#{mint}; Mint.HTTP2.stream/2 decodes every received frame"},
    {mint_clients, "EEF-CVE-2026-56810", :called,
     "#{mint}; Mint.HTTP1.decode_body/5 decodes chunked responses"},
    {mint_clients, "EEF-CVE-2026-58229", :called,
     "#{mint}; Mint.HTTP1.decode_headers/5 decodes every response header block"},
    {mint_clients, "EEF-CVE-2026-59249", :called,
     "#{mint}; Mint.HTTP1.decode_body/5 parses chunk sizes"},
    {mint_clients, "EEF-CVE-2026-82672", :called,
     "#{mint}; Mint.HTTP1.decode_body/5 parses chunk-size lines"},
    {mint_clients, "EEF-CVE-2026-82728", :called, "#{mint}; Mint.HTTP1 decodes every status line"},
    {mint_clients, "EEF-CVE-2026-94194", :called,
     "#{mint}; Mint.HTTP1.stream/2 selects the response body framing"},

    # tesla 1.8.0
    {mint_clients, "EEF-CVE-2026-48597", :called,
     "Tesla.Adapter.Mint.open_conn/2 calls String.to_atom/1 on the scheme of every request URL " <>
       "(tesla/lib/tesla/adapter/mint.ex)"},
    {mint_clients, "EEF-CVE-2026-48596", :not_called,
     "Tesla.Adapter.Mint calls Tesla.Multipart.headers/1 only for a %Tesla.Multipart{} body; " <>
       "the client only sends GET requests without a body"},
    {mint_clients, "EEF-CVE-2026-48598", :not_called,
     "Tesla.Multipart builds part headers only for a %Tesla.Multipart{} body; the client never builds one"},
    {mint_clients, "EEF-CVE-2026-48594", :not_called,
     "the client uses no DecompressResponse or Compression middleware"},
    {mint_clients, "EEF-CVE-2026-48595", :not_called,
     "the client uses no FollowRedirects middleware"},

    # hackney 1.18.1
    {unused_hackney, "EEF-CVE-2026-47069", :not_called, hackney_unused},
    {unused_hackney, "EEF-CVE-2026-47071", :not_called, hackney_unused},
    {unused_hackney, "EEF-CVE-2026-47075", :not_called, hackney_unused},
    {unused_hackney, "EEF-CVE-2026-47076", :not_called, hackney_unused},
    {unused_hackney, "GHSA-9fm9-hp7p-53mf", :not_called, hackney_unused},
    {unused_hackney, "GHSA-vq52-99r9-h5pw", :not_called, hackney_unused},
    {["rebar3_hackney"], "EEF-CVE-2026-47076", :called,
     "rebar_app:fetch/1 calls hackney:get/1, and hackney:request/5 calls hackney_url:normalize/2"},
    {["rebar3_hackney"], "GHSA-vq52-99r9-h5pw", :called,
     "hackney:request/5 parses the caller's URL with hackney_url:parse_url/1"},
    {["rebar3_hackney"], "EEF-CVE-2026-47069", :not_called,
     "hackney_request:perform/2 calls hackney_cookie:setcookie/3 only for a `cookie` option " <>
       "(maybe_add_cookies/2); hackney:get/1 passes no options"},
    {["rebar3_hackney"], "EEF-CVE-2026-47071", :not_called,
     "hackney:maybe_proxy/4 selects the SOCKS5 transport only for a `{proxy, {socks5, _, _}}` " <>
       "option; hackney:get/1 passes no options"},
    {["rebar3_hackney"], "EEF-CVE-2026-47075", :not_called,
     "hackney_url:make_url/3 is a public helper that no hackney module calls"},
    {["rebar3_hackney"], "GHSA-9fm9-hp7p-53mf", :not_called,
     "the leak follows 307 redirects, which hackney:maybe_redirect/2 handles only with " <>
       "`follow_redirect` (false by default)"}
  ],

  # Lowest accepted noise reduction (unreachable / total findings, percent) per
  # project. A scan below the floor fails; a scan above it fails until the
  # floor is raised in the same change.
  noise_floors: %{
    "phoenix_bandit" => 12.0,
    "plug_cowboy_multipart" => 0.0,
    "tesla_mint_hackney" => 24.0,
    "umbrella_three_apps" => 80.0,
    "rebar3_hackney" => 16.7,
    "bandit_tesla_gateway" => 18.4
  }
}
