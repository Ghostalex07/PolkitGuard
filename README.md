# PolkitGuard

[![CI Status](https://github.com/Ghostalex07/PolkitGuard/workflows/CI/badge.svg)](https://github.com/Ghostalex07/PolkitGuard/actions)
[![Go Version](https://img.shields.io/go.mod/go-version/Ghostalex07/PolkitGuard)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Security auditing tool for Linux Polkit policies** - Detecta configuraciones peligrosas que pueden permitir escalada de privilegios.

---

## Instalación Rápida

### Opción 1: Desde código fuente (recomendado)

```bash
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd PolkitGuard
go build -o polkitguard ./cmd/scan

# Ejecutar
./polkitguard scan
```

### Opción 2: Con Go

```bash
go install github.com/Ghostalex07/PolkitGuard/cmd/scan@latest
polkitguard scan
```

### Opción 3: Descargar binario

Ve a [Releases](https://github.com/Ghostalex07/PolkitGuard/releases) y descarga el binario para tu plataforma.

---

## Uso

### Básico

```bash
./polkitguard scan                    # Escanear sistema
./polkitguard --severity high        # Solo CRITICAL y HIGH
./polkitguard --format json          # Output JSON
./polkitguard --format html          # Output HTML
```

### Opciones

| Flag | Descripción | Ejemplo |
|------|-------------|---------|
| `--path` | Directorio a escanear | `--path /etc/polkit` |
| `--severity` | Filtrar por severidad | `--severity high` |
| `--format` | Formato de salida | `--format json` |
| `-q` | Modo silencioso | `-q` |
| `-v` | Verbose | `-v` |
| `-y` | Auto-confirmar | `-y` |

### Códigos de salida

| Código | Significado |
|--------|-------------|
| 0 | Sin problemas |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Critical |

```bash
# Ejemplo en CI/CD
./polkitguard -q
if [ $? -eq 4 ]; then
    echo "¡CRITICAL ISSUES FOUND!"
    exit 1
fi
```

---

## Instalación en Sistema

```bash
# Compilar
go build -o polkitguard ./cmd/scan

# Instalar (como root)
sudo cp polkitguard /usr/local/bin/
sudo chmod 755 /usr/local/bin/polkitguard
```

Ahora可直接 ejecutar `polkitguard` desde cualquier位置.

---

## Qué Detecta

### Critical
- Acceso sin autenticación
- unix-user:* (cualquier usuario)

### High
- unix-group:all
- Acciones con wildcards (*)
- org.freedesktop.* demasiado amplio

### Medium
- Identidad ambigua
- Reglas redundantes

### Low
- Resultados inconsistentes
- Archivos sin comentarios

---

## Estructura del Proyecto

```
polkitguard/
├── cmd/scan/          # Punto de entrada CLI
├── internal/
│   ├── config/       # Configuración
│   ├── detector/     # Reglas de detección
│   ├── models/      # Tipos de datos
│   ├── parser/      # Parser de archivos
│   ├── report/      # Salida (text, JSON, HTML, SARIF)
│   ├── scanner/     # Escaneo de archivos
│   ├── watcher/     # Modo observador
│   └── cis/          # CIS Benchmarks
├── testdata/         # Ejemplos de prueba
├── Makefile          # Comandos de build
└── README.md
```

---

## Para Desarrolladores

```bash
# Desarrollo
make build           # Compilar
make test            # Tests
make vet             # go vet
make fmt            # Formatear código

# Instalación local
make install        # go install
```

---

## Documentación

- [SECURITY.md](SECURITY.md) - Política de seguridad
- [CONTRIBUTING.md](CONTRIBUTING.md) - Cómo contribuir
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Código de conducta
- [CHANGELOG.md](CHANGELOG.md) - Historial de cambios

---

## License

MIT - Ver [LICENSE](LICENSE)