defmodule Mix.Tasks.Vulncheck.Feeds do
  @shortdoc "Manages the advisory feed cache"

  @moduledoc """
  Manages the local advisory cache.

      mix vulncheck.feeds sync
      mix vulncheck.feeds status
      mix vulncheck.feeds bundle --output vulncheck-feeds.tar.gz

    * `sync` — re-downloads the OSV Hex archive and refreshes CVE 5.1
      records, printing advisory and routine counts
    * `status` — prints the cache location, archive age and ETag, and the
      number of cached advisories and CVE records
    * `bundle --output FILE` (`-o`) — exports the cache with a SHA-256
      manifest as a `.tar.gz` for `--offline --bundle FILE` runs

  `--cache-dir DIR` selects another cache directory.
  """

  use Mix.Task

  @requirements ["app.config"]

  @impl Mix.Task
  def run(argv), do: VulnCheck.Mix.exit_with(VulnCheck.CLI.run(["feeds" | argv]))
end
