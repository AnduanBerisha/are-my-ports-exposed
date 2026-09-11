# Are my ports exposed ?

AMPE is a fast, simple Go CLI to verify if your database and internal services are accidentally open to the internet.

## Features

- **Concurrent Auditing**: Probes high-risk service ports simultaneously using lightweight Go routines.
- **Zero External Dependencies**: Built strictly using Go's standard library (`net`, `encoding/json`, `flag`).
- **CI/CD Ready**: Supports structured JSON output and explicit exit status codes.
- **Static Binaries**: Cross-compiled for Linux, macOS, and Windows.

---

## Audited Services

AMPE focuses specifically on databases and management interfaces frequently targeted by automated scans:

| Port | Service | Severity | Description |
|---|---|---|---|
| `21` | FTP | HIGH | Unencrypted file transfer |
| `22` | SSH | INFO | Administrative shell |
| `2375` | Docker Daemon | CRITICAL | Unauthenticated container engine API |
| `3306` | MySQL | CRITICAL | Relational database endpoint |
| `5432` | PostgreSQL | CRITICAL | Relational database endpoint |
| `6379` | Redis | CRITICAL | In-memory datastore |
| `8080` | HTTP-Alt | INFO | Dev/admin web dashboard |
| `9200` | Elasticsearch | CRITICAL | Search engine index and API |
| `27017` | MongoDB | CRITICAL | Document database endpoint |

---

## Installation

### Binary Download

Download the executable matching your platform directly from the GitHub Releases tab.

```bash
# Example for Linux (x86_64)
curl -sL https://github.com/AnduanBerisha/are-my-ports-exposed/releases/latest/download/ampe-linux-amd64 -o ampe
chmod +x ampe
sudo mv ampe /usr/local/bin/
```

### Go Toolchain
```bash
go install github.com/AnduanBerisha/are-my-ports-exposed@latest
```

### From Source
```bash
git clone https://github.com/AnduanBerisha/are-my-ports-exposed.git
cd are-my-ports-exposed
go build -ldflags="-s -w" -o ampe main.go
```

## Usage

### Human-Readable Scan

```bash
ampe -host target-domain-or-ip.com
```

Options:
- `-host string`: Target hostname or IP address (required)
- `-timeout int`: TCP dial timeout in milliseconds (default is 700)
- `-json`: Switch output mode to raw JSON

### Machine-Readable (CI/CD Pipelines)

```bash
ampe -host 198.51.100.24 -json
```

Output:

```json
[
  {
    "service": {
      "port": 6379,
      "name": "Redis",
      "severity": "CRITICAL",
      "description": "In-memory key-value data store"
    },
    "is_open": true
  }
]
```

## Exit Codes

AMPE reports status codes for automated gatekeeping:
- `0`: Scan finished cleanly, no critical exposures detected
- `1`: One or more `CRITICAL`ports are open
- `2`: Invalid CLI parameters or network dial configuration error

## License
[MIT License](LICENSE)