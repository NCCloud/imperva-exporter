# imperva-exporter

```
usage: imperva_exporter.py [-h] [-w] [-i N] [-o N] [-t N] [-v]
                           [--prom-port PORT] [--prom-init-hours N]
                           [--slack-room room-name]
                           [--slack-team <!subteam^ID|@team>]
                           prefix [prefix ...]

Check DDoS events on prefixes protected by Imperva

positional arguments:
  prefix                ip prefix(es), separated by space

optional arguments:
  -h, --help            show this help message and exit
  -w, --watch           keep running and and collect events continuously
  -i N, --interval N    check last N seconds, default: 300
  -o N, --overlap N     compensate latency, default: 300 sec (watch mode only)
  -t N, --threshold N   report after N fails, default: 100 (watch mode only)
  -v, --debug           enable debug output

Prometheus metrics (watch mode only, needs prometheus_client module):
  --prom-port PORT      export Prometheus metrics on this port
  --prom-init-hours N   preload N hours of historical context, default: 24

Slack notifications (watch mode only):
  --slack-room room-name
                        send event notifications to this Slack channel,
                        SLACK_HOOK_URL env must be set
  --slack-team <!subteam^ID|@team>
                        mention this team in the Slack notification

required env vars: IMPERVA_API_ID, IMPERVA_API_KEY, IMPERVA_ACC_ID
```

## Exported Prometheus metrics

| Metric Name                    | Description                            |
| ------------------------------ | -------------------------------------- |
| `imperva_prefix_ddos_status`   | 0 or 1 when the prefix is under attack |
| `imperva_prefix_ddos_total`    | Recorded attacks on the prefix (count) |
| `imperva_api_failure_duration` | Current failure duration in seconds    |
| `imperva_api_errors_total`     | Recorded API/network erros  (count)    |

