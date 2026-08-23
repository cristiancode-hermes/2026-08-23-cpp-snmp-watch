# snmp-watch — architecture

```
/proc/net/snmp          /proc/net/netstat
       \                      /
        +-- slurp + merge ---+
                    |
            parse_snmp_text()
            (skip '#', pair name/value lines)
                    |
              Snapshot + summarize()
                    |
     +--------------+---------------+
     |              |               |
  table/KPI      JSON           watch loop
  (ANSI)      (quoted keys)   (delta + rate)
```

- Gauges (`CurrEstab`, RTO, TTL…) never get a `/s` rate.
- Alert names match Error/Fail/Drop/Abort/Timeout/NoPort/Overflow/Csum/NoRoute.
- First watch frame has no delta; later frames use `dt = now - prev` (fallback: `--watch N`).
