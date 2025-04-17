#!/usr/bin/env python3
"""
flow_mermaid_extractor.py

Scan your Python project for `# flow: SOURCE->DEST: action` comments and generate
a Mermaid flowchart showing the interactions between components (e.g. GUI, API).

Usage:
    1. In your code, annotate cross‑boundary calls:
       # flow: GUI->API: get_ioc_data
       # flow: API->GUI: display_results

    2. Run this script (no arguments if your project root is the default):
       python flow_mermaid_extractor.py

    3. Open `app_flow.mmd` in VS Code (Markdown Preview Mermaid Support) or Mermaid Live Editor.
"""
import os
import re
import argparse

# Regex to match: # flow: Source->Dest: action description
FLOW_RE = re.compile(r'#\s*flow:\s*(\w+)->(\w+):\s*(.+)$')

# Directories to skip during walk
SKIP_DIRS = {'__pycache__', '.venv', 'venv', 'env', 'node_modules', 'dist', 'build', '.git'}


def collect_flows(root):
    """
    Walk through .py files under `root`, collecting any lines with `# flow: X->Y:action`.
    Returns a list of tuples: (source, destination, action).
    """
    flows = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip unwanted directories
        if any(part in SKIP_DIRS for part in dirpath.split(os.sep)):
            continue
        for fn in filenames:
            if not fn.endswith('.py'):
                continue
            full_path = os.path.join(dirpath, fn)
            try:
                with open(full_path, encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        m = FLOW_RE.search(line)
                        if m:
                            src, dst, action = m.groups()
                            flows.append((src, dst, action.strip()))
            except IOError:
                # Could not read file; skip
                continue
    return flows


def render_mermaid(flows):
    """
    Given a list of (src, dst, action), render a Mermaid LR flowchart.
    """
    lines = ["```mermaid", "flowchart LR"]
    seen = set()
    for src, dst, action in flows:
        key = (src, dst, action)
        if key in seen:
            continue
        seen.add(key)
        # Escape any quotes in the action label
        act = action.replace('"', r'\"')
        lines.append(f"    {src} -- \"{act}\" --> {dst}")
    lines.append("```")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Scan for # flow annotations and generate a Mermaid flowchart."
    )
    parser.add_argument(
        'root', nargs='?', default=r"C:\Users\Devel\Desktop\Security Scanner",
        help="Project root directory to scan"
    )
    parser.add_argument(
        '-o', '--output', default='app_flow.mmd',
        help="Output Mermaid filename"
    )
    args = parser.parse_args()

    flows = collect_flows(args.root)
    if not flows:
        print(f"No flow annotations found under: {args.root}")
        return

    mermaid_code = render_mermaid(flows)
    try:
        with open(args.output, 'w', encoding='utf-8') as out_f:
            out_f.write(mermaid_code)
        print(f"✔ Generated {len(flows)} flow edges in '{args.output}'")
    except IOError as e:
        print("✖ Failed to write output file:", e)


if __name__ == '__main__':
    main()
