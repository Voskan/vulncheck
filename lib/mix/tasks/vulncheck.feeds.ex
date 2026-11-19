defmodule Mix.Tasks.Vulncheck.Feeds do
  @shortdoc "Manages the advisory feed cache"

  @moduledoc """
  Manages the local advisory cache.

      mix vulncheck.feeds sync
      mix vulncheck.feeds status
      mix vulncheck.feeds bundle --output vulncheck-feeds.tar.gz
      mix vulncheck.feeds import vulncheck-feeds.tar.gz
      mix vulncheck.feeds prune

    * `sync` — re-downloads the OSV Hex archive and refreshes CVE 5.1
      records, printing advisory and routine counts
    * `status` — prints the cache location, archive age and ETag, the
      number of cached advisories and CVE records, the imported snapshot
      and the snapshot that offline scans read
    * `bundle --output FILE` (`-o`) — exports the cache with a SHA-256
      manifest as a `.tar.gz` for `--offline --bundle FILE` runs
    * `import FILE` — validates a bundle and selects it for later offline
      runs; they read it while it is newer than the live cache
    * `prune` — removes imported snapshots beyond the three most recently
      used ones and module caches of other schema versions

  `--cache-dir DIR` selects another cache directory.
  """

  use Mix.Task

  @requirements ["app.config"]

  @impl Mix.Task
  def run(argv), do: VulnCheck.Mix.run(["feeds" | argv])
end
