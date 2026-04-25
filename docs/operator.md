# Kubernetes Operator for PolkitGuard

This directory contains the Kubernetes Operator SDK integration for PolkitGuard.

## Status: In Development

The operator integration is planned for future versions. For now, please use:

- Helm chart: `examples/helm/`
- Kustomize overlay: `examples/kustomize/`
- kubectl plugin: `examples/kubectl-plugin/`

## Planned Features

- Custom Resource Definition (CRD) for Scanner
- Automatic scheduled scans
- Integration with Prometheus AlertManager
- GitOps integration with ArgoCD/Flux

## Development

To build the operator:

```bash
# Requires Kubernetes Operator SDK
operator-sdk init --domain polkitguard.dev
operator-sdk create api --group security --version v1 --kind Scanner
```

## Resources

- [Operator SDK Documentation](https://sdk.operatorframework.io/)
- [Helm Chart](../helm/)
- [Kustomize](../kustomize/)