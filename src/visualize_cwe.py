#!/usr/bin/env python3
import argparse
import json
import re
from collections import Counter
from pathlib import Path
import matplotlib.pyplot as plt


def find_cwes(obj):
    """Recursively search JSON-like object for CWE identifiers in 'cweId' fields only."""
    cwes = []
    pattern = re.compile(r"CWE-?\d+", re.IGNORECASE)

    if isinstance(obj, dict):
        # Only extract from "cweId" field
        if "cweId" in obj:
            val = obj["cweId"]
            if isinstance(val, str):
                found = pattern.findall(val)
                if found:
                    cwes.extend(found)
        # Recurse into all values
        for v in obj.values():
            cwes.extend(find_cwes(v))
    elif isinstance(obj, list):
        for item in obj:
            cwes.extend(find_cwes(item))

    return cwes


def normalize(cwe):
    c = cwe.upper().replace("CWE", "CWE-")
    c = c.replace("CWE--", "CWE-")
    digits = re.search(r"(\d+)", c)
    if digits:
        return f"CWE-{int(digits.group(1))}"
    return c


def scan_dir(dirpath: Path, recursive: bool = False):
    counter = Counter()
    # If a file was provided, parse that single file
    if dirpath.is_file():
        paths = [dirpath]
    else:
        if recursive:
            paths = sorted(dirpath.rglob("*.json"))
        else:
            paths = sorted(dirpath.glob("*.json"))

    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        found = find_cwes(data)
        found = [normalize(x) for x in found]
        # Remove empty or malformed
        found = [x for x in found if x.startswith("CWE-")]
        # Remove duplicates within the same file (use set)
        found = list(set(found))
        counter.update(found)

    return counter


def plot_counts(counter: Counter, out: Path, top: int = 20, show: bool = False):
    if not counter:
        print("No CWE identifiers found.")
        return

    items = counter.most_common(top)
    labels, counts = zip(*items)

    plt.figure(figsize=(10, max(4, len(labels) * 0.4)))
    y_pos = range(len(labels))
    bars = plt.barh(y_pos, counts, color="#2a7ae2")
    plt.yticks(y_pos, labels)
    plt.gca().invert_yaxis()  # Invert to show highest at top
    plt.xlabel("Count")
    plt.title(f"Top {len(labels)} CWE identifiers")
    
    # Add count values on the bars
    for i, (bar, count) in enumerate(zip(bars, counts)):
        plt.text(count + 0.3, bar.get_y() + bar.get_height()/2, 
                 str(count), va='center', fontsize=9)
    
    plt.tight_layout()
    out.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out, dpi=150)
    print(f"Saved plot to {out}")
    if show:
        plt.show()


def main():
    ap = argparse.ArgumentParser(description="Visualize CWE counts from CVE JSON files")
    ap.add_argument("--dir", default="cve/all", help="Directory or JSON file path with CVE JSON files")
    ap.add_argument("--top", type=int, default=20, help="Top N CWEs to show")
    ap.add_argument("--out", default="figures/cwe/cwe_counts.png", help="Output image path")
    ap.add_argument("--recursive", action="store_true", help="Recursively search subdirectories for JSON files")
    ap.add_argument("--show", action="store_true", help="Display the plot in a window (requires display)")
    args = ap.parse_args()

    dirpath = Path(args.dir)
    out = Path(args.out)
    if not dirpath.exists():
        print(f"Directory not found: {dirpath}")
        raise SystemExit(1)

    counter = scan_dir(dirpath, recursive=args.recursive)
    plot_counts(counter, out, top=args.top, show=args.show)


if __name__ == "__main__":
    main()
