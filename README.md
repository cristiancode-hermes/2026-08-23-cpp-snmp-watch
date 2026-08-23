# snmp-watch

Monitor de contadores SNMP / netstat del kernel Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/snmp` (Ip, Icmp, IcmpMsg, Tcp, Udp, UdpLite) y `/proc/net/netstat`
(TcpExt, IpExt, MPTcpExt) para mostrar KPIs de protocolo, alertas (errores, drops,
timeouts) y tasas entre snapshots.

## Features

- **Parse de `/proc/net/snmp` + `/proc/net/netstat`**: pares `Proto: names` / `Proto: values`
- **Gauges vs counters**: `CurrEstab`, TTL, RTO… no se tratan como tasas
- **Alertas**: Error / Fail / Drop / Abort / Timeout / NoPort / Overflow / Csum / NoRoute
- **Watch mode**: refresco periódico con delta + rate (`/s`) entre snapshots
- **JSON output**: `summary` + objeto `sections` validable
- **Demo mode**: dump sintético con las 9 secciones habituales
- **Filtros**: `--section`, `--nonzero`, `--alerts`
- **`--file`**: parsea un dump (tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 59 checks (parser, filtros, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o snmp-watch
```

## Usage

```bash
# Snapshot único (host real)
./snmp-watch

# Modo watch (cada 2s) con tasas
./snmp-watch --watch 2

# Solo TCP
./snmp-watch --section tcp

# Solo alertas (errores / drops / timeouts)
./snmp-watch --alerts --nonzero

# JSON
./snmp-watch --json

# Demo (dump sintético)
./snmp-watch --demo

# Parsear un dump con comentarios
./snmp-watch --file sample-snmp.table --no-color

# Sin colores
./snmp-watch --no-color

# Auto-tests
./snmp-watch --selftest
```

## Data Source

| Archivo | Secciones |
|---------|-----------|
| `/proc/net/snmp` | Ip, Icmp, IcmpMsg, Tcp, Udp, UdpLite |
| `/proc/net/netstat` | TcpExt, IpExt, MPTcpExt |

Formato kernel: línea de nombres + línea de valores con el mismo prefijo `Proto:`.

### Gauges (no son tasas)

| Nombre | Significado |
|--------|-------------|
| Forwarding / DefaultTTL | config IP |
| RtoAlgorithm / RtoMin / RtoMax / MaxConn | RTO TCP |
| CurrEstab / MPCurrEstab | conexiones establecidas (gauge) |

## Example Output

```
+================================================+
|   Linux SNMP / netstat Protocol Monitor       |
+================================================+
  Source: /proc/net/snmp+/proc/net/netstat

  -- KPIs --
  IP in          1.8M
  TCP estab      18
  Retrans        312
  UDP NoPorts    14
  Octets in      2.32 GiB
  ListenDrops    7

  -- Counters (N) --
  [Tcp]
  Tcp        CurrEstab                  18  gauge
  Tcp        RetransSegs               312
  TcpExt     ListenDrops                 7  alert
```

## License

MIT
