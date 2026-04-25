Gem::Specification.new do |spec|
  spec.name          = "polkitguard"
  spec.version       = "1.18.0"
  spec.authors       = ["Ghostalex07"]
  spec.email         = ["ghostalex07@example.com"]
  spec.summary       = "Security scanner for Linux Polkit policies"
  spec.description   = "PolkitGuard is a comprehensive security scanner for Linux Polkit policies that detects vulnerabilities and provides remediation recommendations."
  spec.homepage      = "https://github.com/Ghostalex07/PolkitGuard"
  spec.license       = "MIT"
  spec.files         = ["lib/polkitguard.rb", "lib/polkitguard/version.rb", "lib/polkitguard/scanner.rb", "lib/polkitguard/models.rb", "bin/polkitguard"]
  spec.bindir        = "bin"
  spec.executables   = ["polkitguard"]
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.7"

  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rake", "~> 13.0"
end