defmodule VulnCheck.Config do
  @moduledoc """
  Scan configuration resolved from command-line flags, `.vulncheck.exs` and
  built-in defaults (in that order of precedence).

  `.vulncheck.exs` is a declarative keyword list. It is parsed with
  `VulnCheck.Literal`, which never evaluates code and never creates atoms:
  only literals, whitelisted option values and module aliases are accepted.

      [
        env: :prod,
        fail_on: :potentially_reachable,
        min_severity: :low,
        fail_on_retired: true,
        configured_adapters: [tesla: Tesla.Adapter.Mint],
        extra_entrypoints: [{MyApp.ReleaseTasks, :migrate, 0}],
        ignore_file: ".vulncheck.ignore",
        require_ignore_reason: true,
        require_ignore_expiry: true,
        cache_dir: nil,
        cache_ttl_seconds: 3600
      ]
  """

  alias VulnCheck.Literal
  alias VulnCheck.Types.MFA

  @formats [:terminal, :json, :markdown, :sarif, :github, :gitlab, :cyclonedx, :openvex]
  @fail_on [:reachable, :potentially_reachable, :any, :none]
  @severities [:low, :medium, :high, :critical]
  @envs [:prod, :dev, :test]
  @adapter_families [:tesla, :swoosh, :ecto, :phoenix_pubsub]

  defstruct project_dir: ".",
            config_file: nil,
            env: :prod,
            format: :terminal,
            output: nil,
            sarif: nil,
            sbom: nil,
            vex: nil,
            fail_on: :potentially_reachable,
            min_severity: :low,
            fail_on_retired: true,
            check_retired: true,
            show_unreachable: false,
            diff: nil,
            baseline: nil,
            write_baseline: nil,
            forbid_new_suppressions: false,
            otp_version: nil,
            offline: false,
            bundle: nil,
            configured_adapters: %{},
            extra_entrypoints: [],
            ignore_file: ".vulncheck.ignore",
            require_ignore_reason: true,
            require_ignore_expiry: false,
            cache_dir: nil,
            feed_snapshot: nil,
            feed_selection: nil,
            cache_ttl_seconds: 3600,
            max_feed_age_seconds: nil,
            beam_timeout: 15_000,
            max_beam_files: 20_000,
            max_beam_bytes: 64 * 1024 * 1024,
            max_beam_heap_bytes: 128 * 1024 * 1024,
            color: true,
            quiet: false,
            force: false,
            args: []

  @type format :: :terminal | :json | :markdown | :sarif | :github | :gitlab | :cyclonedx | :openvex
  @type fail_on :: :reachable | :potentially_reachable | :any | :none
  @type min_severity :: :low | :medium | :high | :critical

  @type t :: %__MODULE__{
          project_dir: String.t(),
          config_file: String.t() | nil,
          env: :prod | :dev | :test,
          format: format(),
          output: String.t() | nil,
          sarif: String.t() | nil,
          sbom: String.t() | nil,
          vex: String.t() | nil,
          fail_on: fail_on(),
          min_severity: min_severity(),
          fail_on_retired: boolean(),
          check_retired: boolean(),
          show_unreachable: boolean(),
          diff: String.t() | nil,
          baseline: String.t() | nil,
          write_baseline: String.t() | nil,
          forbid_new_suppressions: boolean(),
          otp_version: String.t() | nil,
          offline: boolean(),
          bundle: String.t() | nil,
          configured_adapters: %{atom() => [String.t()]},
          extra_entrypoints: [MFA.t()],
          ignore_file: String.t(),
          require_ignore_reason: boolean(),
          require_ignore_expiry: boolean(),
          cache_dir: String.t() | nil,
          feed_snapshot: String.t() | nil,
          feed_selection: map() | nil,
          cache_ttl_seconds: non_neg_integer(),
          max_feed_age_seconds: non_neg_integer() | nil,
          beam_timeout: pos_integer(),
          max_beam_files: pos_integer(),
          max_beam_bytes: pos_integer(),
          max_beam_heap_bytes: pos_integer(),
          color: boolean(),
          quiet: boolean(),
          force: boolean(),
          args: [String.t()]
        }

  @switches [
    project_dir: :string,
    config: :string,
    env: :string,
    format: :string,
    output: :string,
    sarif: :string,
    sbom: :string,
    vex: :string,
    fail_on: :string,
    min_severity: :string,
    fail_on_retired: :boolean,
    retired: :boolean,
    show_unreachable: :boolean,
    diff: :string,
    baseline: :string,
    write_baseline: :string,
    forbid_new_suppressions: :boolean,
    otp_version: :string,
    offline: :boolean,
    bundle: :string,
    ignore_file: :string,
    cache_dir: :string,
    cache_ttl: :integer,
    max_feed_age: :integer,
    color: :boolean,
    quiet: :boolean,
    force: :boolean
  ]

  @aliases [o: :output, f: :format, q: :quiet]

  @file_keys ~w(env format output sarif sbom vex fail_on min_severity fail_on_retired check_retired
                show_unreachable otp_version offline bundle configured_adapters extra_entrypoints
                ignore_file require_ignore_reason require_ignore_expiry cache_dir cache_ttl_seconds max_feed_age_seconds
                beam_timeout max_beam_files max_beam_bytes max_beam_heap_bytes
                forbid_new_suppressions diff baseline)

  @doc "Supported output formats."
  @spec formats() :: [format()]
  def formats, do: @formats

  @doc "Supported `--fail-on` tiers."
  @spec fail_on_values() :: [fail_on()]
  def fail_on_values, do: @fail_on

  @doc "Supported adapter families for `configured_adapters`."
  @spec adapter_families() :: [atom()]
  def adapter_families, do: @adapter_families

  @doc "The OptionParser switches understood by every scanning command."
  @spec switches() :: keyword()
  def switches, do: @switches

  @doc "The OptionParser aliases understood by every scanning command."
  @spec aliases() :: keyword()
  def aliases, do: @aliases

  @doc """
  Builds a configuration from CLI arguments and the project's `.vulncheck.exs`.

  Precedence: CLI flags > `.vulncheck.exs` > defaults.

  Options:

    * `:cwd` — directory used to resolve a relative `--project-dir` (default: `File.cwd!/0`)
    * `:extra_switches` — additional OptionParser switches accepted by a subcommand
    * `:allow_args` — when `true`, positional arguments are kept in `config.args`
      instead of being rejected
  """
  @spec from_cli_and_file([String.t()], keyword()) :: {:ok, t()} | {:error, String.t()}
  def from_cli_and_file(argv, opts \\ []) when is_list(argv) do
    switches = @switches ++ Keyword.get(opts, :extra_switches, [])

    case OptionParser.parse(argv, strict: switches, aliases: @aliases) do
      {parsed, args, []} ->
        with :ok <- check_args(args, opts),
             {:ok, base} <- base_config(parsed, opts),
             {:ok, file_config} <- load_file(base),
             {:ok, config} <- apply_cli(file_config, expand_cli_paths(parsed, opts)) do
          {:ok, %{config | args: args}}
        end

      {_parsed, _args, invalid} ->
        {:error, "invalid option(s): " <> format_invalid(invalid)}
    end
  end

  @doc """
  Loads a `.vulncheck.exs` file (or any declarative config file) and merges it
  into the given configuration.
  """
  @spec load_file(t()) :: {:ok, t()} | {:error, String.t()}
  def load_file(%__MODULE__{} = config) do
    path = config.config_file || Path.join(config.project_dir, ".vulncheck.exs")

    cond do
      File.regular?(path) ->
        with {:ok, term} <- parse_config_file(path) do
          merge_file_options(%{config | config_file: path}, term, path)
        end

      config.config_file != nil ->
        {:error, "configuration file not found: #{path}"}

      true ->
        {:ok, config}
    end
  end

  @doc """
  Parses a declarative configuration file without evaluating it.
  """
  @spec parse_config_file(Path.t()) :: {:ok, Literal.lterm()} | {:error, String.t()}
  def parse_config_file(path) do
    case Literal.parse_file(path) do
      {:ok, term} when is_list(term) ->
        {:ok, term}

      {:ok, _other} ->
        {:error, "#{path}: configuration must be a keyword list"}

      {:error, {:unsafe_expression, line, code}} ->
        {:error,
         "#{path}:#{line}: only literal values are allowed in configuration files, got: #{code}"}

      {:error, {:file_error, _path, reason}} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}

      {:error, message} when is_binary(message) ->
        {:error, message}
    end
  end

  @doc """
  Returns the severity rank used for threshold comparisons (`critical` = 4).
  Unknown severities rank as `:critical` (fail-safe).
  """
  @spec severity_rank(atom()) :: non_neg_integer()
  def severity_rank(:low), do: 1
  def severity_rank(:none), do: 1
  def severity_rank(:medium), do: 2
  def severity_rank(:high), do: 3
  def severity_rank(:critical), do: 4
  def severity_rank(_unknown), do: 4

  @doc "Absolute path of the scanned project."
  @spec project_root(t()) :: String.t()
  def project_root(%__MODULE__{project_dir: dir}), do: Path.expand(dir)

  @doc "Absolute path of the ignore file."
  @spec ignore_path(t()) :: String.t()
  def ignore_path(%__MODULE__{ignore_file: file} = config),
    do: Path.expand(file, project_root(config))

  @doc false
  def validate_output_paths(%__MODULE__{} = config) do
    paths =
      for key <- [:output, :sarif, :sbom, :vex, :write_baseline],
          path = Map.fetch!(config, key),
          is_binary(path),
          do: {Path.expand(path, project_root(config)), key}

    paths
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.sort()
    |> Enum.find(fn {_path, keys} -> length(keys) > 1 end)
    |> case do
      nil ->
        :ok

      {path, keys} ->
        flags = Enum.map_join(keys, ", ", &("--" <> String.replace(Atom.to_string(&1), "_", "-")))
        {:error, "output destinations overlap (#{flags}): #{path}"}
    end
  end

  # -- CLI ---------------------------------------------------------------------

  defp check_args([], _opts), do: :ok

  defp check_args(args, opts) do
    if Keyword.get(opts, :allow_args, false) do
      :ok
    else
      {:error, "unexpected argument(s): " <> Enum.join(args, " ")}
    end
  end

  defp base_config(parsed, opts) do
    cwd = Keyword.get_lazy(opts, :cwd, &File.cwd!/0)
    project_dir = Path.expand(Keyword.get(parsed, :project_dir, "."), cwd)

    config_file =
      case Keyword.fetch(parsed, :config) do
        {:ok, path} -> Path.expand(path, cwd)
        :error -> nil
      end

    if File.dir?(project_dir) do
      {:ok, %__MODULE__{project_dir: project_dir, config_file: config_file}}
    else
      {:error, "project directory does not exist: #{project_dir}"}
    end
  end

  # Paths given on the command line are relative to the working directory;
  # paths in `.vulncheck.exs` are relative to the project root.
  defp expand_cli_paths(parsed, opts) do
    cwd = Keyword.get_lazy(opts, :cwd, &File.cwd!/0)

    Enum.map(parsed, fn
      {key, value}
      when key in [
             :output,
             :sarif,
             :sbom,
             :vex,
             :baseline,
             :write_baseline,
             :bundle,
             :ignore_file,
             :cache_dir
           ] and
             value != "" ->
        {key, Path.expand(value, cwd)}

      other ->
        other
    end)
  end

  defp apply_cli(config, parsed) do
    Enum.reduce_while(parsed, {:ok, config}, fn {key, value}, {:ok, acc} ->
      case apply_cli_option(acc, key, value) do
        {:ok, acc} -> {:cont, {:ok, acc}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp apply_cli_option(config, key, _value) when key in [:project_dir, :config],
    do: {:ok, config}

  defp apply_cli_option(config, :env, value),
    do: with_enum(config, :env, value, @envs, "--env")

  defp apply_cli_option(config, :format, value),
    do: with_enum(config, :format, value, @formats, "--format")

  defp apply_cli_option(config, :fail_on, value),
    do: with_enum(config, :fail_on, value, @fail_on, "--fail-on")

  defp apply_cli_option(config, :min_severity, value),
    do: with_enum(config, :min_severity, value, @severities, "--min-severity")

  defp apply_cli_option(config, :retired, value), do: {:ok, %{config | check_retired: value}}

  defp apply_cli_option(config, :cache_ttl, value) when value >= 0,
    do: {:ok, %{config | cache_ttl_seconds: value}}

  defp apply_cli_option(_config, :cache_ttl, _value),
    do: {:error, "--cache-ttl must be a non-negative integer"}

  defp apply_cli_option(config, :max_feed_age, value) when value >= 0,
    do: {:ok, %{config | max_feed_age_seconds: value}}

  defp apply_cli_option(_config, :max_feed_age, _value),
    do: {:error, "--max-feed-age must be a non-negative integer"}

  defp apply_cli_option(config, :otp_version, value) do
    if Regex.match?(~r/\A\d+(\.\d+)*\z/, value) do
      {:ok, %{config | otp_version: value}}
    else
      {:error, "invalid value for --otp-version: #{inspect(value)} (expected e.g. 27 or 26.2)"}
    end
  end

  defp apply_cli_option(config, key, value)
       when key in [
              :output,
              :sarif,
              :sbom,
              :vex,
              :diff,
              :baseline,
              :write_baseline,
              :bundle,
              :ignore_file,
              :cache_dir
            ] do
    if value == "" do
      {:error, "--#{dasherize(key)} requires a non-empty value"}
    else
      {:ok, Map.put(config, key, value)}
    end
  end

  defp apply_cli_option(config, key, value)
       when key in [
              :fail_on_retired,
              :show_unreachable,
              :forbid_new_suppressions,
              :offline,
              :color,
              :quiet,
              :force
            ] do
    {:ok, Map.put(config, key, value)}
  end

  defp apply_cli_option(config, _key, _value), do: {:ok, config}

  defp with_enum(config, key, value, allowed, flag) do
    case Enum.find(allowed, &(Atom.to_string(&1) == normalize_choice(value))) do
      nil ->
        {:error,
         "invalid value for #{flag}: #{inspect(value)} (expected one of: " <>
           Enum.map_join(allowed, ", ", &Atom.to_string/1) <> ")"}

      atom ->
        {:ok, Map.put(config, key, atom)}
    end
  end

  defp normalize_choice(value),
    do: value |> String.trim() |> String.downcase() |> String.replace("-", "_")

  defp format_invalid(invalid) do
    Enum.map_join(invalid, ", ", fn
      {option, nil} -> option
      {option, value} -> "#{option} #{value}"
    end)
  end

  defp dasherize(key), do: key |> Atom.to_string() |> String.replace("_", "-")

  # -- File --------------------------------------------------------------------

  defp merge_file_options(config, term, path) do
    case Literal.keyword_pairs(term) do
      {:ok, pairs} ->
        Enum.reduce_while(pairs, {:ok, config}, fn {key, value}, {:ok, acc} ->
          case file_option(acc, key, value) do
            {:ok, acc} -> {:cont, {:ok, acc}}
            {:error, message} -> {:halt, {:error, "#{path}: #{message}"}}
          end
        end)

      :error ->
        {:error, "#{path}: configuration must be a keyword list"}
    end
  end

  defp file_option(_config, key, _value) when key not in @file_keys,
    do: {:error, "unknown configuration key #{inspect(key)}"}

  defp file_option(config, "env", value), do: file_enum(config, :env, value, @envs)
  defp file_option(config, "format", value), do: file_enum(config, :format, value, @formats)
  defp file_option(config, "fail_on", value), do: file_enum(config, :fail_on, value, @fail_on)

  defp file_option(config, "min_severity", value),
    do: file_enum(config, :min_severity, value, @severities)

  defp file_option(config, key, value)
       when key in ~w(fail_on_retired check_retired show_unreachable offline require_ignore_reason
                      require_ignore_expiry forbid_new_suppressions) do
    if is_boolean(value) do
      {:ok, Map.put(config, String.to_existing_atom(key), value)}
    else
      {:error, "#{key} must be a boolean"}
    end
  end

  defp file_option(config, key, value)
       when key in ~w(output sarif sbom vex bundle ignore_file cache_dir diff baseline) do
    cond do
      is_nil(value) and key not in ["ignore_file"] ->
        {:ok, Map.put(config, String.to_existing_atom(key), nil)}

      is_binary(value) and value != "" ->
        resolved =
          if key in ~w(output sarif sbom vex bundle cache_dir baseline),
            do: Path.expand(value, project_root(config)),
            else: value

        {:ok, Map.put(config, String.to_existing_atom(key), resolved)}

      true ->
        {:error, "#{key} must be a non-empty string"}
    end
  end

  defp file_option(config, "otp_version", value) do
    cond do
      is_nil(value) ->
        {:ok, %{config | otp_version: nil}}

      is_integer(value) and value > 0 ->
        {:ok, %{config | otp_version: Integer.to_string(value)}}

      is_binary(value) and Regex.match?(~r/\A\d+(\.\d+)*\z/, value) ->
        {:ok, %{config | otp_version: value}}

      true ->
        {:error, "otp_version must be a version string such as \"27\""}
    end
  end

  defp file_option(config, "cache_ttl_seconds", value) do
    if is_integer(value) and value >= 0 do
      {:ok, %{config | cache_ttl_seconds: value}}
    else
      {:error, "cache_ttl_seconds must be a non-negative integer"}
    end
  end

  defp file_option(config, "max_feed_age_seconds", nil),
    do: {:ok, %{config | max_feed_age_seconds: nil}}

  defp file_option(config, "max_feed_age_seconds", value) do
    if is_integer(value) and value >= 0 do
      {:ok, %{config | max_feed_age_seconds: value}}
    else
      {:error, "max_feed_age_seconds must be a non-negative integer or nil"}
    end
  end

  defp file_option(config, key, value)
       when key in ~w(beam_timeout max_beam_files max_beam_bytes max_beam_heap_bytes) do
    if is_integer(value) and value > 0 do
      {:ok, Map.put(config, String.to_existing_atom(key), value)}
    else
      {:error, "#{key} must be a positive integer"}
    end
  end

  defp file_option(config, "configured_adapters", value) do
    with {:ok, pairs} <- adapter_pairs(value) do
      adapters =
        Enum.reduce(pairs, config.configured_adapters, fn {family, modules}, acc ->
          Map.update(acc, family, modules, &Enum.uniq(&1 ++ modules))
        end)

      {:ok, %{config | configured_adapters: adapters}}
    end
  end

  defp file_option(config, "extra_entrypoints", value) when is_list(value) do
    Enum.reduce_while(value, {:ok, []}, fn entry, {:ok, acc} ->
      case entrypoint(entry) do
        {:ok, mfa} -> {:cont, {:ok, [mfa | acc]}}
        :error -> {:halt, {:error, "invalid extra_entrypoints entry: #{inspect(entry)}"}}
      end
    end)
    |> case do
      {:ok, mfas} -> {:ok, %{config | extra_entrypoints: Enum.reverse(mfas)}}
      error -> error
    end
  end

  defp file_option(_config, "extra_entrypoints", _value),
    do: {:error, "extra_entrypoints must be a list of {Module, :function, arity} tuples"}

  defp file_enum(config, key, {:atom, name}, allowed) do
    case Enum.find(allowed, &(Atom.to_string(&1) == name)) do
      nil ->
        {:error,
         "invalid value :#{name} for #{key} (expected one of: " <>
           Enum.map_join(allowed, ", ", &inspect/1) <> ")"}

      atom ->
        {:ok, Map.put(config, key, atom)}
    end
  end

  defp file_enum(_config, key, value, _allowed),
    do: {:error, "#{key} must be an atom, got: #{inspect(value)}"}

  defp adapter_pairs(value) do
    case Literal.keyword_pairs(value) do
      {:ok, pairs} ->
        Enum.reduce_while(pairs, {:ok, []}, fn {family, modules}, {:ok, acc} ->
          with {:ok, family_atom} <- adapter_family(family),
               {:ok, names} <- adapter_modules(modules) do
            {:cont, {:ok, [{family_atom, names} | acc]}}
          else
            {:error, _} = error -> {:halt, error}
          end
        end)

      :error ->
        {:error, "configured_adapters must be a keyword list such as [tesla: Tesla.Adapter.Mint]"}
    end
  end

  defp adapter_family(family) do
    case Enum.find(@adapter_families, &(Atom.to_string(&1) == family)) do
      nil ->
        {:error,
         "unknown adapter family #{inspect(family)} (supported: " <>
           Enum.map_join(@adapter_families, ", ", &Atom.to_string/1) <> ")"}

      atom ->
        {:ok, atom}
    end
  end

  defp adapter_modules({:alias, name}), do: {:ok, [name]}
  defp adapter_modules({:atom, name}), do: {:ok, [MFA.normalize_module(name)]}

  defp adapter_modules(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case adapter_modules(item) do
        {:ok, names} -> {:cont, {:ok, acc ++ names}}
        error -> {:halt, error}
      end
    end)
  end

  defp adapter_modules(other),
    do: {:error, "adapter must be a module alias, got: #{inspect(other)}"}

  defp entrypoint({:tuple, [module, {:atom, function}, arity]})
       when is_integer(arity) and arity >= 0 do
    case module do
      {:alias, name} -> {:ok, MFA.new(name, function, arity)}
      {:atom, name} -> {:ok, MFA.new(MFA.normalize_module(name), function, arity)}
      _ -> :error
    end
  end

  defp entrypoint(routine) when is_binary(routine) do
    case MFA.parse_routine(routine) do
      {:ok, mfa} -> {:ok, mfa}
      :error -> :error
    end
  end

  defp entrypoint(_), do: :error
end
