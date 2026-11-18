defmodule VulnCheck.Workspace.GitUrl do
  @moduledoc """
  Normalizes Git dependency URLs into canonical `owner/repo` slugs without
  creating atoms.
  """

  @doc """
  Extracts a lowercased `"owner/repo"` slug from HTTPS, SSH, `git://` or
  `owner/repo` strings. Returns `:error` for unrecognized or local URLs.
  """
  @spec normalize_repo(String.t() | nil) :: {:ok, String.t()} | :error
  def normalize_repo(url) when is_binary(url) do
    url = String.trim(url)

    cond do
      url == "" ->
        :error

      String.contains?(url, "://") ->
        case URI.parse(url) do
          %URI{host: host, path: path}
          when is_binary(host) and host != "" and is_binary(path) ->
            extract_slug(path)

          _ ->
            :error
        end

      Regex.match?(~r/\A[^@\s]+@[^:\s]+:[^\s]+\z/, url) ->
        [_user_host, path] = String.split(url, ":", parts: 2)
        extract_slug(path)

      Regex.match?(~r/\A[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\z/, url) ->
        extract_slug(url)

      true ->
        :error
    end
  end

  def normalize_repo(_), do: :error

  @doc "Returns the normalized `owner/repo` slug or `nil`."
  @spec repo_slug(String.t() | nil) :: String.t() | nil
  def repo_slug(url) do
    case normalize_repo(url) do
      {:ok, slug} -> slug
      :error -> nil
    end
  end

  defp extract_slug(path) do
    parts =
      path
      |> String.trim_leading("/")
      |> String.trim_trailing("/")
      |> String.trim_trailing(".git")
      |> String.split("/", trim: true)

    case parts do
      [owner, repo | _] when owner != "" and repo != "" ->
        {:ok, String.downcase("#{owner}/#{repo}")}

      _ ->
        :error
    end
  end
end
