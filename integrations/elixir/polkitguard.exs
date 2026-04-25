-- PolkitGuard Elixir Package
defmodule PolkitGuard do
  @moduledoc """
  Security scanner for Linux Polkit policies.
  """

  alias PolkitGuard.{Scanner, Finding, ScanResult, RiskScore}

  @version "1.18.0"

  @doc """
  Get version string.
  """
  def version, do: @version

  @doc """
  Run a scan on the default polkit paths.
  """
  def scan(severity \\ "low") do
    Scanner.scan(nil, severity)
  end

  @doc """
  Run a scan on a specific path.
  """
  def scan_path(path, severity \\ "low") do
    Scanner.scan(path, severity)
  end

  @doc """
  Run async scan.
  """
  def scan_async(severity \\ "low") do
    Task.async(fn -> scan(severity) end)
  end

  @doc """
  Run multiple scans concurrently.
  """
  def scan_multiple(paths, severity \\ "low") do
    paths
    |> Enum.map(fn path -> Task.async(fn -> scan_path(path, severity) end) end)
    |> Enum.map(&Task.await/1)
  end

  @doc """
  Calculate risk score from findings.
  """
  def calculate_risk_score(findings) do
    RiskScore.calculate(findings)
  end

  @doc """
  Check if system is healthy (no critical findings).
  """
  def healthy?(severity \\ "low") do
    result = scan(severity)
    Enum.empty?(result.critical_findings)
  end
end

defmodule PolkitGuard.Scanner do
  @moduledoc false

  @binary "polkitguard"

  def scan(path \\ nil, severity \\ "low") do
    args = ["--format", "json", "--severity", severity]
    args = if path, do: args ++ ["--path", path], else: args

    case System.cmd(@binary, args, stderr_to_stdout: true) do
      {output, 0} ->
        output
        |> Jason.decode!()
        |> to_scan_result()

      {error, _} ->
        raise "PolkitGuard scan failed: #{error}"
    end
  end

  defp to_scan_result(data) do
    findings = Enum.map(data["findings"] || [], &to_finding/1)
    stats = data["stats"] || %{}

    %PolkitGuard.ScanResult{
      findings: findings,
      files_scanned: stats["files_scanned"] || 0,
      rules_found: stats["rules_found"] || 0,
      scanner: data["scanner"] || "PolkitGuard",
      version: data["version"] || @version
    }
  end

  defp to_finding(data) do
    %PolkitGuard.Finding{
      severity: data["Severity"] || 1,
      file: data["File"],
      rule_name: data["RuleName"],
      rule_id: data["RuleID"],
      title: data["Title"],
      description: data["Description"],
      message: data["Message"],
      rule: to_rule(data["Rule"])
    }
  end

  defp to_rule(nil), do: nil
  defp to_rule(data) do
    %PolkitGuard.Rule{
      action: data["Action"],
      identity: data["Identity"],
      result_any: data["ResultAny"]
    }
  end
end

defmodule PolkitGuard.Finding do
  @moduledoc false
  defstruct [
    :severity,
    :file,
    :rule_name,
    :rule_id,
    :title,
    :description,
    :message,
    :rule
  ]

  def critical?(%__MODULE__{severity: s}), do: s == 4
  def high?(%__MODULE__{severity: s}), do: s == 3
end

defmodule PolkitGuard.ScanResult do
  @moduledoc false
  defstruct [
    :findings,
    :files_scanned,
    :rules_found,
    :scanner,
    :version
  ]

  def critical_findings(%__MODULE__{findings: f}), do: Enum.filter(f, &PolkitGuard.Finding.critical?/1)
  def high_findings(%__MODULE__{findings: f}), do: Enum.filter(f, &PolkitGuard.Finding.high?/1)
end

defmodule PolkitGuard.Rule do
  @moduledoc false
  defstruct [:action, :identity, :result_any, :result_active, :result_inactive]
end

defmodule PolkitGuard.RiskScore do
  @moduledoc false
  defstruct [:overall, :level, :criticality, :likelihood, :impact, :recommendations]

  def calculate(findings) do
    counts = Enum.reduce(findings, {0, 0, 0, 0}, fn
      f, {c, h, m, l} when f.severity == 4 -> {c + 1, h, m, l}
      f, {c, h, m, l} when f.severity == 3 -> {c, h + 1, m, l}
      f, {c, h, m, l} when f.severity == 2 -> {c, h, m + 1, l}
      f, {c, h, m, l} -> {c, h, m, l + 1}
    end)

    {critical, high, medium, low} = counts
    total = max(length(findings), 1)
    score = (critical * 10 + high * 7 + medium * 4 + low * 1) / total

    level = cond do
      score >= 8 -> "CRITICAL"
      score >= 6 -> "HIGH"
      score >= 4 -> "MEDIUM"
      score >= 2 -> "LOW"
      true -> "MINIMAL"
    end

    recommendations = []
    recommendations = if critical > 0, do: ["URGENT: Critical issues found" | recommendations], else: recommendations
    recommendations = if high > 0, do: ["High priority: Review within 24 hours" | recommendations], else: recommendations

    %__MODULE__{
      overall: score,
      level: level,
      criticality: critical / total * 10,
      likelihood: high / total * 10,
      impact: (critical + high) / total * 10,
      recommendations: recommendations
    }
  end
end

defmodule PolkitGuard.MixProject do
  use Mix.Project

  def project do
    [
      app: :polkitguard,
      version: "1.18.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [{:jason, "~> 1.4"}]
  end
end