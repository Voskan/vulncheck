defmodule VulnCheck.Test.HTTPServer do
  @moduledoc false
  # A tiny HTTP/1.1 server on 127.0.0.1 used to exercise the real HTTP client
  # without any external network access. Each response closes the connection.

  use GenServer

  import ExUnit.Callbacks, only: [on_exit: 1]

  @type handler :: (map() -> {non_neg_integer(), [{String.t(), String.t()}], iodata()})

  @doc "Starts a server for the current test and returns its base URL."
  @spec start!(handler()) :: %{url: String.t(), pid: pid()}
  def start!(handler) do
    {:ok, pid} = GenServer.start(__MODULE__, handler)
    port = GenServer.call(pid, :port)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    %{url: "http://127.0.0.1:#{port}", pid: pid}
  end

  @doc "Returns the list of requests received so far (oldest first)."
  def requests(%{pid: pid}), do: GenServer.call(pid, :requests)

  @doc "Replaces the request handler."
  def set_handler(%{pid: pid}, handler), do: GenServer.call(pid, {:set_handler, handler})

  @impl true
  def init(handler) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        backlog: 128,
        packet: :raw
      ])

    {:ok, port} = :inet.port(listen)
    server = self()
    acceptor = spawn_link(fn -> accept_loop(listen, server) end)
    {:ok, %{listen: listen, port: port, handler: handler, requests: [], acceptor: acceptor}}
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}
  def handle_call(:requests, _from, state), do: {:reply, Enum.reverse(state.requests), state}

  def handle_call({:set_handler, handler}, _from, state),
    do: {:reply, :ok, %{state | handler: handler}}

  def handle_call({:request, request}, _from, state) do
    response =
      try do
        state.handler.(request)
      rescue
        error -> {500, [], Exception.message(error)}
      end

    {:reply, response, %{state | requests: [request | state.requests]}}
  end

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.listen)
    :ok
  end

  defp accept_loop(listen, server) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn(fn -> serve(socket, server) end)
        :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept_loop(listen, server)

      {:error, _} ->
        :ok
    end
  end

  defp serve(socket, server) do
    receive do
      :go -> :ok
    after
      1_000 -> :ok
    end

    with {:ok, raw} <- read_head(socket, ""),
         request = parse(raw),
         {status, headers, body} <- safe_call(server, request) do
      body = IO.iodata_to_binary(body)

      head =
        ["HTTP/1.1 #{status} #{reason(status)}\r\n"] ++
          Enum.map(headers, fn {k, v} -> "#{k}: #{v}\r\n" end) ++
          ["content-length: #{byte_size(body)}\r\n", "connection: close\r\n", "\r\n"]

      :gen_tcp.send(socket, [head, body])
    end

    :gen_tcp.close(socket)
  end

  defp safe_call(server, request) do
    GenServer.call(server, {:request, request}, 30_000)
  catch
    :exit, _ -> :error
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, data} -> read_head(socket, acc <> data)
        error -> error
      end
    end
  end

  defp parse(raw) do
    [head | _] = String.split(raw, "\r\n\r\n", parts: 2)
    [request_line | header_lines] = String.split(head, "\r\n")
    [method, path | _] = String.split(request_line, " ")

    headers =
      Map.new(header_lines, fn line ->
        [k, v] = String.split(line, ":", parts: 2)
        {String.downcase(k), String.trim(v)}
      end)

    %{method: method, path: path, headers: headers}
  end

  defp reason(200), do: "OK"
  defp reason(304), do: "Not Modified"
  defp reason(301), do: "Moved Permanently"
  defp reason(302), do: "Found"
  defp reason(404), do: "Not Found"
  defp reason(500), do: "Internal Server Error"
  defp reason(503), do: "Service Unavailable"
  defp reason(_), do: "Status"
end
