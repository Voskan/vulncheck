defmodule VulnCheck.Types.VersionRange do
  @moduledoc """
  A single affected version interval.

    * `introduced` — first affected version (inclusive); `nil` or `"0"` means
      "every version since the beginning".
    * `fixed` — first unaffected version (exclusive upper bound).
    * `last_affected` — last affected version (inclusive upper bound).

  When both `fixed` and `last_affected` are `nil` the interval is open-ended.
  """

  defstruct introduced: nil, fixed: nil, last_affected: nil

  @type t :: %__MODULE__{
          introduced: String.t() | nil,
          fixed: String.t() | nil,
          last_affected: String.t() | nil
        }
end

defmodule VulnCheck.Types.Retirement do
  @moduledoc """
  Hex.pm retirement metadata attached to a specific package release.
  """

  @enforce_keys [:package, :version, :reason]
  defstruct [:package, :version, :reason, message: ""]

  @type reason :: :security | :invalid | :deprecated | :renamed | :other

  @type t :: %__MODULE__{
          package: String.t(),
          version: String.t(),
          reason: reason(),
          message: String.t()
        }
end

defmodule VulnCheck.Types.Advisory do
  @moduledoc """
  A security advisory (or a Hex retirement notice) bound to one package.

  OSV records affecting several packages are split into one `Advisory` per
  package so that version matching and reachability are evaluated per
  dependency.
  """

  alias VulnCheck.Types.{MFA, Retirement, VersionRange}

  @type severity :: :critical | :high | :medium | :low | :unknown

  @enforce_keys [:id, :package]
  defstruct [
    :id,
    aliases: [],
    package: "",
    summary: "",
    details: "",
    severity: :unknown,
    cvss_score: nil,
    cvss_vector: nil,
    cwes: [],
    references: [],
    published_at: nil,
    modified_at: nil,
    version_ranges: [],
    affected_versions: [],
    fixed_versions: [],
    affected_modules: [],
    affected_routines: [],
    otp_constraints: nil,
    retirement: nil,
    symbol_source: nil,
    enriched: false
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          aliases: [String.t()],
          package: String.t(),
          summary: String.t(),
          details: String.t(),
          severity: severity(),
          cvss_score: float() | nil,
          cvss_vector: String.t() | nil,
          cwes: [String.t()],
          references: [String.t()],
          published_at: String.t() | nil,
          modified_at: String.t() | nil,
          version_ranges: [VersionRange.t()],
          affected_versions: [String.t()],
          fixed_versions: [String.t()],
          affected_modules: [String.t()],
          affected_routines: [MFA.t()],
          otp_constraints: String.t() | nil,
          retirement: Retirement.t() | nil,
          symbol_source: :cve | :osv | :text | nil,
          enriched: boolean()
        }

  @severities [:critical, :high, :medium, :low, :unknown]

  @doc "All severities from most to least severe."
  @spec severities() :: [severity()]
  def severities, do: @severities

  @doc """
  Maps a CVSS base score to a qualitative severity.

      iex> VulnCheck.Types.Advisory.severity_from_score(9.8)
      :critical
      iex> VulnCheck.Types.Advisory.severity_from_score(nil)
      :unknown
  """
  @spec severity_from_score(number() | nil) :: severity()
  def severity_from_score(nil), do: :unknown
  def severity_from_score(score) when score >= 9.0, do: :critical
  def severity_from_score(score) when score >= 7.0, do: :high
  def severity_from_score(score) when score >= 4.0, do: :medium
  def severity_from_score(score) when score > 0.0, do: :low
  def severity_from_score(_score), do: :unknown

  @doc """
  The more severe of two severities; `:unknown` loses to any known severity.

      iex> VulnCheck.Types.Advisory.max_severity(:medium, :high)
      :high
      iex> VulnCheck.Types.Advisory.max_severity(:unknown, :low)
      :low
  """
  @spec max_severity(severity(), severity()) :: severity()
  def max_severity(a, b) do
    if Enum.find_index(@severities, &(&1 == a)) <= Enum.find_index(@severities, &(&1 == b)),
      do: a,
      else: b
  end

  @doc """
  Parses a qualitative severity label (`"HIGH"`, `"moderate"`, ...) without
  creating atoms.
  """
  @spec parse_severity(String.t() | nil) :: severity()
  def parse_severity(label) when is_binary(label) do
    case label |> String.trim() |> String.downcase() do
      "critical" -> :critical
      "high" -> :high
      "important" -> :high
      "medium" -> :medium
      "moderate" -> :medium
      "low" -> :low
      _ -> :unknown
    end
  end

  def parse_severity(_), do: :unknown

  @doc """
  Returns the primary CVE identifier of an advisory, if any.

      iex> VulnCheck.Types.Advisory.cve_id(%VulnCheck.Types.Advisory{id: "EEF-CVE-2026-101028", package: "ash"})
      "CVE-2026-101028"
  """
  @spec cve_id(t()) :: String.t() | nil
  def cve_id(%__MODULE__{id: id, aliases: aliases}) do
    Enum.find_value([id | aliases], fn candidate ->
      case Regex.run(~r/(CVE-\d{4}-\d{4,})/, candidate || "") do
        [_, cve] -> cve
        _ -> nil
      end
    end)
  end

  @doc "Returns all identifiers (primary id plus aliases), de-duplicated."
  @spec identifiers(t()) :: [String.t()]
  def identifiers(%__MODULE__{id: id, aliases: aliases} = advisory) do
    [id, cve_id(advisory) | aliases]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end
end
