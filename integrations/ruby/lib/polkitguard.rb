require_relative "polkitguard/version"
require_relative "polkitguard/models"
require_relative "polkitguard/scanner"

module PolkitGuard
  def self.scan(path: nil, severity: "low")
    Scanner.new.scan(path: path, severity: severity)
  end

  def self.risk_score(findings)
    RiskScore.new(findings)
  end
end