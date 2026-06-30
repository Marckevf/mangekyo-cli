"""Demo: run `mangekyo explain` against three public hosts in sequence."""
import subprocess, sys
py = sys.executable
ips = ["8.8.8.8", "1.1.1.1", "45.33.32.156"]
for ip in ips:
    print(f"\n{'#'*65}")
    print(f"# SCORING: {ip}")
    print(f"{'#'*65}", flush=True)
    r = subprocess.run([py, "-m", "mangekyo.cli.main", "explain", ip],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(r.stdout, flush=True)
    if r.stderr: print("STDERR:", r.stderr[:500], flush=True)
