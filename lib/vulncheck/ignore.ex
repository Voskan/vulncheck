defmodule VulnCheck.Ignore do
  @moduledoc """
  Governed suppressions from `.vulncheck.ignore`.

  The file holds a list of maps (or keyword lists) and is parsed as data,
  never evaluated:

      [
        %{
          id: "CVE-2026-54892",
          package: "plug",
          reason: "WAF blocks nested query depth > 4; upgrade scheduled",
          expires: "2027-01-31"
        }
      ]

  A rule matches a finding by advisory id or any alias, optionally limited
  to one package. Rules without a reason (when `require_ignore_reason`) or
  without a valid expiry (when `require_ignore_expiry`) are rejected with a
  warning. Expired rules do not suppress: the finding is flagged with
  `suppression_expired` and the scan reports a policy violation.
  """

  alias VulnCheck.{Config, Git, Literal}
  alias VulnCheck.Types.Finding

  defmodule Rule do
    @moduledoc "One suppression entry."
    @enforce_keys [:id]
    defstruct [:id, :package, :reason, :expires, :line]

    @type t :: %__MODULE__{
            id: String.t(),
            package: String.t() | nil,
            reason: String.t() | nil,
            expires: Date.t() | nil,
            line: pos_integer() | nil
          }
  end

  @doc """
  Parses ignore file contents. Returns the valid rules and warnings for
  rejected entries.
  """
  @spec parse(String.t(), Config.t(), keyword()) ::
          {:ok, [Rule.t()], [String.t()]} | {:error, String.t()}
  def parse(source, %Config{} = config, opts \\ []) do
    file = Keyword.get(opts, :file, ".vulncheck.ignore")

    with {:ok, term} <- literal(source, file) do
      case term do
        entries when is_list(entries) ->
          {rules, warnings} =
            entries
            |> Enum.with_index(1)
            |> Enum.map(fn {entry, index} -> rule(entry, index, config, file) end)
            |> Enum.split_with(&match?({:ok, _}, &1))

          {:ok, Enum.map(rules, &elem(&1, 1)), Enum.map(warnings, &elem(&1, 1))}

        _ ->
          {:error, "#{file}: expected a list of suppression entries"}
      end
    end
  end

  @doc """
  Loads the configured ignore file. A missing file yields no rules.
  """
  @spec load(Config.t()) :: {:ok, [Rule.t()], [String.t()]} | {:error, String.t()}
  def load(%Config{} = config) do
    path = Config.ignore_path(config)

    case File.read(path) do
      {:ok, source} ->
        parse(source, config, file: Path.relative_to(path, Config.project_root(config)))

      {:error, :enoent} ->
        {:ok, [], []}

      {:error, reason} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  @doc """
  Applies rules to findings as of `today`. Returns the updated findings,
  policy violations (expired suppressions) and warnings (unused rules).
  """
  @spec apply_rules([Finding.t()], [Rule.t()], Date.t()) ::
          {[Finding.t()], [String.t()], [String.t()]}
  def apply_rules(findings, rules, %Date{} = today) do
    {findings, {used, conflicts}} =
      Enum.map_reduce(findings, {MapSet.new(), []}, fn finding, {used, conflicts} ->
        matching = Enum.filter(rules, &matches?(&1, finding))
        used = Enum.reduce(matching, used, &MapSet.put(&2, &1))

        case preferred_rules(matching) do
          [] ->
            {finding, {used, conflicts}}

          [%Rule{} = rule] ->
            expired? = rule.expires != nil and Date.compare(today, rule.expires) == :gt

            finding = %{
              finding
              | suppressed: not expired?,
                suppression_expired: expired?,
                suppression_reason: rule.reason,
                suppression_expires: rule.expires && Date.to_iso8601(rule.expires)
            }

            {finding, {used, conflicts}}

          _conflicting ->
            message = "conflicting suppressions for #{finding.advisory_id} (#{finding.package})"
            {finding, {used, [message | conflicts]}}
        end
      end)

    violations =
      for %Finding{suppression_expired: true} = f <- findings do
        "suppression of #{f.advisory_id} (#{f.package}) expired on #{f.suppression_expires}"
      end
      |> Enum.uniq()

    warnings =
      for rule <- rules, not MapSet.member?(used, rule) do
        "suppression of #{rule.id}#{if rule.package, do: " (#{rule.package})"} matches no finding"
      end

    {findings, Enum.uniq(violations ++ Enum.reverse(conflicts)), warnings}
  end

  defp preferred_rules(rules) do
    specific = Enum.reject(rules, &is_nil(&1.package))
    candidates = if specific == [], do: rules, else: specific
    Enum.uniq_by(candidates, &{&1.reason, &1.expires})
  end

  @doc """
  Post-processing step for `VulnCheck.Scanner`: loads the ignore file,
  applies it and, with `forbid_new_suppressions`, checks it against the
  base revision.
  """
  @spec step(keyword()) :: (list(), map() -> {list(), [String.t()], [String.t()]})
  def step(opts \\ []) do
    fn findings, %{config: config} ->
      today = Keyword.get_lazy(opts, :today, &Date.utc_today/0)

      case load(config) do
        {:ok, rules, warnings} ->
          {findings, violations, more} = apply_rules(findings, rules, today)
          guard = if config.forbid_new_suppressions, do: new_suppressions(config, rules), else: []
          {findings, violations ++ guard, warnings ++ more}

        {:error, message} ->
          {findings, ["cannot read suppressions: #{message}"], []}
      end
    end
  end

  @doc """
  Compares the current rules with the ignore file at the base revision
  (`config.diff`, else `origin/main` or `HEAD~1`). New entries and
  extended expiry dates are violations; so is an unverifiable base.
  """
  @spec new_suppressions(Config.t(), [Rule.t()]) :: [String.t()]
  def new_suppressions(%Config{} = config, rules) do
    root = Config.project_root(config)
    relative = Path.relative_to(Config.ignore_path(config), root)

    with {:ok, base} <- Git.default_base(root, config.diff),
         {:ok, base_rules} <- base_rules(root, base, relative, config) do
      known = Enum.group_by(base_rules, &{&1.id, &1.package}, & &1.expires)

      Enum.flat_map(rules, fn %Rule{} = rule ->
        case Map.fetch(known, {rule.id, rule.package}) do
          :error ->
            ["new suppression of #{rule.id} added since #{base}"]

          {:ok, expiries} ->
            case Enum.uniq(expiries) do
              [old] ->
                if extended?(old, rule.expires),
                  do: ["suppression of #{rule.id} extended since #{base}"],
                  else: []

              _ ->
                ["conflicting base suppressions for #{rule.id} at #{base}"]
            end
        end
      end)
    else
      {:error, reason} ->
        if rules == [],
          do: [],
          else: ["cannot verify suppressions against the base revision: #{inspect(reason)}"]
    end
  end

  defp base_rules(root, base, relative, config) do
    # Validation rules of the base file do not matter here, only its entries.
    lenient = %{config | require_ignore_reason: false, require_ignore_expiry: false}

    case Git.show(root, base, relative) do
      {:ok, source} ->
        case parse(source, lenient) do
          {:ok, rules, _} -> {:ok, rules}
          {:error, _} -> {:ok, []}
        end

      {:error, :not_found} ->
        {:ok, []}

      error ->
        error
    end
  end

  defp extended?(nil, nil), do: false
  defp extended?(_old, nil), do: true
  defp extended?(nil, _new), do: false
  defp extended?(old, new), do: Date.compare(new, old) == :gt

  defp matches?(%Rule{id: id, package: package}, %Finding{} = finding) do
    (package == nil or package == finding.package) and id in [finding.advisory_id | finding.aliases]
  end

  defp literal(source, file) do
    case Literal.parse(source, file: file) do
      {:ok, term} ->
        {:ok, term}

      {:error, {:unsafe_expression, line, code}} ->
        {:error, "#{file}:#{line}: not a literal: #{code}"}

      {:error, message} ->
        {:error, message}
    end
  end

  defp rule(entry, index, config, file) do
    fields =
      case entry do
        {:map, _pairs} = map -> map
        list when is_list(list) -> list
        _ -> nil
      end

    with pairs when not is_nil(pairs) <- fields,
         id when is_binary(id) and id != "" <- get(pairs, "id") do
      reason = get(pairs, "reason")
      expires = get(pairs, "expires")
      package = get(pairs, "package")

      cond do
        not (is_binary(package) or is_nil(package)) ->
          {:error, "#{file}: entry #{index} (#{id}): package must be a string"}

        config.require_ignore_reason and not (is_binary(reason) and String.trim(reason) != "") ->
          {:error, "#{file}: entry #{index} (#{id}) rejected: a reason is required"}

        expires != nil and not match?({:ok, _}, parse_date(expires)) ->
          {:error,
           "#{file}: entry #{index} (#{id}) rejected: invalid expires date #{inspect(expires)}"}

        config.require_ignore_expiry and expires == nil ->
          {:error, "#{file}: entry #{index} (#{id}) rejected: an expires date is required"}

        true ->
          {:ok,
           %Rule{
             id: id,
             package: package,
             reason: if(is_binary(reason), do: reason),
             expires: if(expires, do: elem(parse_date(expires), 1)),
             line: index
           }}
      end
    else
      _ -> {:error, "#{file}: entry #{index} rejected: an id is required"}
    end
  end

  defp get(pairs, key), do: Literal.kw_get(pairs, key)

  defp parse_date(value) when is_binary(value), do: Date.from_iso8601(value)
  defp parse_date(_value), do: :error
end
