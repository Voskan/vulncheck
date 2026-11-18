defmodule VulnCheck.HTTPTest do
  use ExUnit.Case, async: true

  alias VulnCheck.HTTP
  alias VulnCheck.Test.HTTPServer

  @fast [retry_delay_ms: 1, timeout: 5_000]

  test "performs GET requests against a local listener" do
    server =
      HTTPServer.start!(fn %{path: "/feed"} = request ->
        {200, [{"etag", "\"v1\""}, {"content-type", "application/json"}],
         ~s({"ua":"#{request.headers["user-agent"]}"})}
      end)

    assert {:ok, %{status: 200, headers: headers, body: body}} =
             HTTP.get(server.url <> "/feed", [], @fast)

    assert headers["etag"] == "\"v1\""
    assert body =~ "vulncheck/"
    assert HTTP.user_agent() =~ VulnCheck.version()
  end

  test "returns non-2xx statuses without raising" do
    server = HTTPServer.start!(fn _ -> {404, [], "missing"} end)
    assert {:ok, %{status: 404, body: "missing"}} = HTTP.get(server.url <> "/x", [], @fast)
  end

  test "rejects partial responses and preserves conditional GET statuses" do
    server =
      HTTPServer.start!(fn
        %{path: "/range"} -> {206, [{"content-range", "bytes 0-3/10"}], "part"}
        %{path: "/ranges"} -> {206, [{"content-type", "multipart/byteranges; boundary=b"}], ""}
        %{path: "/unchanged"} -> {304, [{"etag", "\"v1\""}], ""}
        %{path: "/complete"} -> {200, [], "complete"}
      end)

    assert {:error, :partial_response} = HTTP.get(server.url <> "/range", [], @fast)
    assert {:error, _reason} = HTTP.get(server.url <> "/ranges", [], @fast)
    assert {:ok, %{status: 304, body: ""}} = HTTP.get(server.url <> "/unchanged", [], @fast)
    assert {:ok, %{status: 200, body: "complete"}} = HTTP.get(server.url <> "/complete", [], @fast)
  end

  test "retries transient 503 responses" do
    counter = :counters.new(1, [])

    server =
      HTTPServer.start!(fn _ ->
        :counters.add(counter, 1, 1)

        if :counters.get(counter, 1) < 3,
          do: {503, [], "busy"},
          else: {200, [], "ok"}
      end)

    assert {:ok, %{status: 200, body: "ok"}} = HTTP.get(server.url <> "/r", [], @fast)
    assert length(HTTPServer.requests(server)) == 3
  end

  test "gives up after the retry budget" do
    server = HTTPServer.start!(fn _ -> {503, [], "busy"} end)
    assert {:ok, %{status: 503}} = HTTP.get(server.url <> "/r", [], [retries: 1] ++ @fast)
    assert length(HTTPServer.requests(server)) == 2
  end

  test "refuses plain http to non-loopback hosts" do
    assert {:error, {:insecure_url, "http://example.com/x"}} = HTTP.get("http://example.com/x")
    assert {:error, {:invalid_url, _}} = HTTP.get("ftp://example.com/x")
    assert {:error, {:invalid_url, _}} = HTTP.validate_url(nil)
    assert :ok = HTTP.validate_url("https://osv-vulnerabilities.storage.googleapis.com/Hex/all.zip")
    assert :ok = HTTP.validate_url("http://localhost:4000/x")
  end

  test "uses strict TLS verification" do
    opts = HTTP.ssl_options()
    assert opts[:verify] == :verify_peer
    assert is_list(opts[:cacerts]) and opts[:cacerts] != []
    assert opts[:customize_hostname_check][:match_fun]
  end

  @tag capture_log: true
  test "requires both a trusted TLS chain and a matching hostname" do
    san = {:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"localhost"}]}
    cert_opts = [digest: :sha256, key: {:namedCurve, :secp256r1}]
    chain = %{root: cert_opts, intermediates: [], peer: cert_opts}

    %{server_config: server_opts, client_config: client_opts} =
      :public_key.pkix_test_data(%{
        server_chain: %{chain | peer: [extensions: [san]] ++ cert_opts},
        client_chain: chain
      })

    {:ok, listener} =
      :ssl.listen(0, [mode: :binary, active: false, ip: {127, 0, 0, 1}] ++ server_opts)

    on_exit(fn -> :ssl.close(listener) end)
    {:ok, {_, port}} = :ssl.sockname(listener)

    server = Task.async(fn -> Enum.map(1..3, fn _ -> serve_tls(listener) end) end)
    hostname = "https://localhost:#{port}/"
    opts = [cacerts: client_opts[:cacerts], retries: 0] ++ @fast

    assert {:ok, %{status: 200, body: "tls"}} = HTTP.get(hostname, [], opts)
    assert {:error, {:failed_connect, _}} = HTTP.get("https://127.0.0.1:#{port}/", [], opts)
    assert {:error, {:failed_connect, _}} = HTTP.get(hostname, [], [retries: 0] ++ @fast)
    assert [:ok, {:error, _}, {:error, _}] = Task.await(server, 15_000)
  end

  test "aborts oversized bodies" do
    server = HTTPServer.start!(fn _ -> {200, [], String.duplicate("a", 10_000)} end)

    assert {:error, {:body_too_large, 100}} =
             HTTP.get(server.url <> "/big", [], [max_body_bytes: 100] ++ @fast)

    server404 = HTTPServer.start!(fn _ -> {404, [], String.duplicate("b", 10_000)} end)

    assert {:error, {:body_too_large, 100}} =
             HTTP.get(server404.url <> "/big", [], [max_body_bytes: 100] ++ @fast)
  end

  test "follows safe redirects and rejects insecure ones" do
    target = HTTPServer.start!(fn _ -> {200, [], "moved here"} end)

    redirecting =
      HTTPServer.start!(fn
        %{path: "/ok"} -> {302, [{"location", target.url <> "/new"}], ""}
        %{path: "/bad"} -> {301, [{"location", "http://example.com/evil"}], ""}
        %{path: "/loop"} -> {302, [{"location", "/loop"}], ""}
        %{path: "/nowhere"} -> {302, [], ""}
      end)

    assert {:ok, %{body: "moved here"}} = HTTP.get(redirecting.url <> "/ok", [], @fast)

    assert {:error, {:insecure_url, "http://example.com/evil"}} =
             HTTP.get(redirecting.url <> "/bad", [], @fast)

    assert {:error, :too_many_redirects} = HTTP.get(redirecting.url <> "/loop", [], @fast)
    assert {:error, {:http_status, 302}} = HTTP.get(redirecting.url <> "/nowhere", [], @fast)
  end

  test "times out slow servers" do
    server =
      HTTPServer.start!(fn _ ->
        Process.sleep(1_500)
        {200, [], "late"}
      end)

    assert {:error, :timeout} =
             HTTP.get(server.url <> "/slow", [], timeout: 200, retries: 0, retry_delay_ms: 0)
  end

  test "reports connection failures" do
    {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(listen)
    :gen_tcp.close(listen)

    assert {:error, {:failed_connect, _}} =
             HTTP.get("http://127.0.0.1:#{port}/", [], retries: 1, retry_delay_ms: 1)
  end

  defp serve_tls(listener) do
    {:ok, socket} = :ssl.transport_accept(listener, 5_000)

    try do
      with {:ok, connection} <- :ssl.handshake(socket, 5_000),
           {:ok, _request} <- :ssl.recv(connection, 0, 5_000) do
        :ssl.send(
          connection,
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntls"
        )
      end
    after
      :ssl.close(socket)
    end
  end
end
