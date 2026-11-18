defmodule VulnCheck.HTTP do
  @moduledoc """
  Minimal, hardened HTTP client built on `:httpc` and `:ssl`.

    * `https://` requests always verify the peer certificate against the
      operating system trust store (`:public_key.cacerts_get/0`) and check the
      hostname.
    * Plain `http://` is only allowed for loopback hosts (local test servers).
    * Successful responses are streamed with backpressure and aborted beyond
      `:max_body_bytes` (default 50 MiB). For other responses, `:httpc` delivers
      the buffered body before the client can check its size.
    * Partial responses are rejected because feed requests require a complete body.
    * Transient failures (`502`, `503`, `504`, timeouts, closed sockets) are
      retried up to two times with jitter.
    * Redirects are followed manually (at most 3) so every hop is validated.

  The module implements the `VulnCheck.HTTP` behaviour itself; tests and
  embedders can pass any other implementation through the `:http_client`
  option accepted by the feed modules.
  """

  @type response :: %{
          status: non_neg_integer(),
          headers: %{String.t() => String.t()},
          body: binary()
        }

  @callback get(url :: String.t(), headers :: [{String.t(), String.t()}], opts :: keyword()) ::
              {:ok, response()} | {:error, term()}

  @behaviour __MODULE__

  @default_timeout 15_000
  @default_connect_timeout 5_000
  @default_max_body 50 * 1024 * 1024
  @transient_statuses [502, 503, 504]
  @loopback_hosts ["127.0.0.1", "localhost", "::1", "[::1]"]
  @max_redirects 3

  @doc "The `User-Agent` header value sent with every request."
  @spec user_agent() :: String.t()
  def user_agent, do: "vulncheck/#{VulnCheck.version()} (+https://github.com/Voskan/vulncheck)"

  @doc """
  Performs a GET request.

  Options: `:timeout`, `:connect_timeout`, `:max_body_bytes`, `:retries`
  (default 2), `:retry_delay_ms` (default 300) and `:cacerts` (trusted DER
  certificates, defaults to the operating system trust store).
  """
  @impl true
  @spec get(String.t(), [{String.t(), String.t()}], keyword()) ::
          {:ok, response()} | {:error, term()}
  def get(url, headers \\ [], opts \\ []) do
    with :ok <- validate_url(url),
         :ok <- ensure_started() do
      retries = Keyword.get(opts, :retries, 2)
      do_get(url, headers, opts, retries, 0, @max_redirects)
    end
  end

  @doc """
  Validates that a URL may be requested: `https://` anywhere, `http://` only
  on loopback hosts.
  """
  @spec validate_url(String.t()) :: :ok | {:error, term()}
  def validate_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} when is_binary(host) and host != "" ->
        :ok

      %URI{scheme: "http", host: host} when host in @loopback_hosts ->
        :ok

      %URI{scheme: "http"} ->
        {:error, {:insecure_url, url}}

      _ ->
        {:error, {:invalid_url, url}}
    end
  end

  def validate_url(url), do: {:error, {:invalid_url, url}}

  @doc "TLS options used for `https://` requests."
  @spec ssl_options(keyword()) :: keyword()
  def ssl_options(opts \\ []) do
    [
      verify: :verify_peer,
      cacerts: Keyword.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0),
      depth: 4,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]
  end

  defp ensure_started do
    with {:ok, _} <- Application.ensure_all_started(:inets),
         {:ok, _} <- Application.ensure_all_started(:ssl) do
      :ok
    else
      {:error, reason} -> {:error, {:http_unavailable, reason}}
    end
  end

  defp do_get(url, headers, opts, retries_left, attempt, redirects_left) do
    case request(url, headers, opts) do
      {:ok, %{status: status} = response} when status in [301, 302, 303, 307, 308] ->
        follow_redirect(url, response, headers, opts, redirects_left)

      {:ok, %{status: status}} = result when status in @transient_statuses ->
        if retries_left > 0 do
          backoff(attempt, opts)
          do_get(url, headers, opts, retries_left - 1, attempt + 1, redirects_left)
        else
          result
        end

      {:ok, _response} = result ->
        result

      {:error, reason} = error ->
        if retries_left > 0 and transient?(reason) do
          backoff(attempt, opts)
          do_get(url, headers, opts, retries_left - 1, attempt + 1, redirects_left)
        else
          error
        end
    end
  end

  defp follow_redirect(_url, _response, _headers, _opts, 0), do: {:error, :too_many_redirects}

  defp follow_redirect(url, response, headers, opts, redirects_left) do
    case Map.get(response.headers, "location") do
      nil ->
        {:error, {:http_status, response.status}}

      location ->
        target = url |> URI.merge(location) |> URI.to_string()

        with :ok <- validate_url(target) do
          retries = Keyword.get(opts, :retries, 2)
          do_get(target, headers, opts, retries, 0, redirects_left - 1)
        end
    end
  end

  defp transient?(:timeout), do: true
  defp transient?({:failed_connect, _}), do: true
  defp transient?(:socket_closed_remotely), do: true
  defp transient?({:closed, _}), do: true
  defp transient?(:closed), do: true
  defp transient?(_), do: false

  defp backoff(attempt, opts) do
    base = Keyword.get(opts, :retry_delay_ms, 300)

    if base > 0 do
      Process.sleep(base * (attempt + 1) + :rand.uniform(max(base, 1)))
    end
  end

  defp request(url, headers, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    max_body = Keyword.get(opts, :max_body_bytes, @default_max_body)

    request_headers =
      [{"user-agent", user_agent()}, {"accept-encoding", "identity"} | headers]
      |> Enum.map(fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    http_opts =
      [
        timeout: timeout,
        connect_timeout: Keyword.get(opts, :connect_timeout, @default_connect_timeout),
        autoredirect: false
      ] ++ if(URI.parse(url).scheme == "https", do: [ssl: ssl_options(opts)], else: [])

    options = [sync: false, stream: {:self, :once}, body_format: :binary]

    case :httpc.request(:get, {String.to_charlist(url), request_headers}, http_opts, options) do
      {:ok, ref} -> receive_response(ref, max_body, timeout + 1_000)
      {:error, reason} -> {:error, normalize_error(reason)}
    end
  end

  defp receive_response(ref, max_body, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    receive_loop(ref, max_body, deadline, nil, [], 0)
  end

  defp receive_loop(ref, max_body, deadline, stream, acc, size) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:http, {^ref, :stream_start, raw_headers, pid}} ->
        headers = normalize_headers(raw_headers)

        if partial?(headers) do
          cancel(ref, :partial_response)
        else
          :httpc.stream_next(pid)
          receive_loop(ref, max_body, deadline, {pid, headers}, acc, size)
        end

      {:http, {^ref, :stream, chunk}} ->
        {pid, _headers} = stream
        size = size + byte_size(chunk)

        if size > max_body do
          cancel(ref, {:body_too_large, max_body})
        else
          :httpc.stream_next(pid)
          receive_loop(ref, max_body, deadline, stream, [acc, chunk], size)
        end

      {:http, {^ref, :stream_end, raw_headers}} ->
        {_pid, headers} = stream
        headers = Map.merge(headers, normalize_headers(raw_headers))

        if partial?(headers),
          do: {:error, :partial_response},
          else: {:ok, %{status: 200, headers: headers, body: IO.iodata_to_binary(acc)}}

      {:http, {^ref, {{_version, 206, _reason}, _headers, _body}}} ->
        {:error, :partial_response}

      {:http, {^ref, {{_version, status, _reason}, raw_headers, body}}} ->
        body = IO.iodata_to_binary(body)

        if byte_size(body) > max_body do
          {:error, {:body_too_large, max_body}}
        else
          {:ok, %{status: status, headers: normalize_headers(raw_headers), body: body}}
        end

      {:http, {^ref, {:error, reason}}} ->
        {:error, normalize_error(reason)}
    after
      remaining ->
        cancel(ref, :timeout)
    end
  end

  # OTP streams both 200 and 206 without a status line. A single range is
  # marked by Content-Range, while multiple ranges use a multipart media type.
  defp partial?(headers) do
    media_type = headers |> Map.get("content-type", "") |> String.downcase()

    Map.has_key?(headers, "content-range") or
      String.starts_with?(media_type, "multipart/byteranges")
  end

  defp cancel(ref, reason) do
    :httpc.cancel_request(ref)
    flush(ref)
    {:error, reason}
  end

  defp flush(ref) do
    receive do
      {:http, {^ref, _}} -> flush(ref)
      {:http, {^ref, _, _}} -> flush(ref)
      {:http, {^ref, _, _, _}} -> flush(ref)
    after
      0 -> :ok
    end
  end

  defp normalize_headers(headers) do
    Map.new(headers, fn {k, v} ->
      {k |> to_string() |> String.downcase(), to_string(v)}
    end)
  end

  defp normalize_error({:failed_connect, [{:to_address, _}, {_, _, reason}]}),
    do: {:failed_connect, reason}

  defp normalize_error({:failed_connect, details}), do: {:failed_connect, details}
  defp normalize_error(reason), do: reason
end
