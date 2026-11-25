defmodule VulnCheck.Workspace.GitUrl do
  @moduledoc """
  Normalizes Git dependency URLs into canonical repository slugs without
  creating atoms.

  GitHub URLs (and bare `owner/repo` strings) normalize to `"owner/repo"`.
  Non-GitHub hosts (GitLab, Bitbucket, self-hosted Git servers) retain their
  lowercased hostname and full path segments (e.g.
  `"gitlab.com/group/subgroup/repo"`, `"git.corp.internal/owner/repo"`) so
  they never collide with GitHub advisories or truncate GitLab subgroups.
  """

  @github_hosts ["github.com", "www.github.com"]

  @doc """
  Extracts a lowercased repository slug from HTTPS, SSH, `git://`, SCP-style
  `user@host:path` or bare `owner/repo` strings. Returns `:error` for
  unrecognized, local (`file://`), single-segment or malformed URLs.
  """
  @spec normalize_repo(String.t() | nil) :: {:ok, String.t()} | :error
  def normalize_repo(url) when is_binary(url) do
    url = String.trim(url)

    cond do
      url == "" ->
        :error

      String.contains?(url, "://") ->
        case URI.parse(url) do
          %URI{scheme: scheme, host: host, path: path}
          when scheme != "file" and is_binary(host) and host != "" and is_binary(path) ->
            format_slug(String.downcase(host), path)

          _ ->
            :error
        end

      Regex.match?(~r/\A[^@\s]+@[^:\s]+:[^\s]+\z/, url) ->
        [user_host, path] = String.split(url, ":", parts: 2)
        [_user, host] = String.split(user_host, "@", parts: 2)

        if host == "" do
          :error
        else
          format_slug(String.downcase(host), path)
        end

      Regex.match?(~r/\A[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+(?:\.git)?\z/i, url) ->
        format_slug(nil, url)

      true ->
        :error
    end
  end

  def normalize_repo(_), do: :error

  @doc "Returns the normalized repository slug or `nil`."
  @spec repo_slug(String.t() | nil) :: String.t() | nil
  def repo_slug(url) do
    case normalize_repo(url) do
      {:ok, slug} -> slug
      :error -> nil
    end
  end

  @doc """
  Extracts `{owner, repo}` (lowercased, `.git` stripped) ONLY when `url` refers
  to `github.com` (or `www.github.com`). Returns `nil` for non-GitHub hosts,
  spoofed hostnames such as `not-github.com`, or bare strings without a host.
  """
  @spec github_repo(String.t() | nil) :: {String.t(), String.t()} | nil
  def github_repo(url) when is_binary(url) do
    url = String.trim(url)

    case parse_host_and_path(url) do
      {host, path} when host in @github_hosts ->
        case format_slug(host, path) do
          {:ok, slug} ->
            case String.split(slug, "/") do
              [owner, repo] -> {owner, repo}
              _ -> nil
            end

          :error ->
            nil
        end

      _ ->
        nil
    end
  end

  def github_repo(_), do: nil

  defp parse_host_and_path(url) do
    cond do
      String.contains?(url, "://") ->
        case URI.parse(url) do
          %URI{scheme: scheme, host: host, path: path}
          when scheme != "file" and is_binary(host) and host != "" and is_binary(path) ->
            {String.downcase(host), path}

          _ ->
            nil
        end

      Regex.match?(~r/\A[^@\s]+@[^:\s]+:[^\s]+\z/, url) ->
        [user_host, path] = String.split(url, ":", parts: 2)
        [_user, host] = String.split(user_host, "@", parts: 2)
        if host == "", do: nil, else: {String.downcase(host), path}

      true ->
        nil
    end
  end

  defp format_slug(host, path) do
    trimmed =
      path
      |> String.trim_leading("/")
      |> String.trim_trailing("/")
      |> then(&Regex.replace(~r/\.git\z/i, &1, ""))

    parts = String.split(trimmed, "/", trim: false)

    if length(parts) >= 2 and Enum.all?(parts, &(&1 != "" and &1 not in [".", ".."])) do
      full_path = parts |> Enum.join("/") |> String.downcase()

      if host in [nil | @github_hosts] do
        {:ok, full_path}
      else
        {:ok, "#{host}/#{full_path}"}
      end
    else
      :error
    end
  end
end
