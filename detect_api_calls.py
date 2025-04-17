#!/usr/bin/env python3
"""
detect_api_calls.py

Loopt recursief door je project (root) en vindt alle requests.<method> calls
in je eigen .py-bestanden. Mappen als .venv, venv, env, __pycache__ worden
overgeslagen. Rapporteert per call zowel de HTTP‑methode, regelnummer als URL.

Usage:
    python detect_api_calls.py [-o OUTPUT_TXT] [-m OUTPUT_MMD] [root]
    (root defaults to de huidige directory)
"""

import os
import ast
import argparse

# Mappen die we willen overslaan
IGNORE_DIRS = {
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".git",
    "node_modules",
}

# Welke HTTP-methodes we willen detecteren
HTTP_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "head",
    "patch",
    "options",
}

def extract_url_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    elif isinstance(node, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) else "{...}"
            for part in node.values
        )
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return extract_url_string(node.left) + extract_url_string(node.right)
    elif isinstance(node, ast.Name):
        return f"<var:{node.id}>"
    elif isinstance(node, ast.Call):
        return "<func()>"
    return "<onbekende URL>"

def find_api_calls_in_file(path):
    calls = []
    try:
        source = open(path, encoding="utf-8").read()
        tree = ast.parse(source, filename=path)
    except Exception:
        return calls

    class CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Attribute) \
               and isinstance(node.func.value, ast.Name) \
               and node.func.value.id == "requests":
                method = node.func.attr.lower()
                if method in HTTP_METHODS:
                    url = extract_url_string(node.args[0]) if node.args else "<geen argument>"
                    calls.append((method, node.lineno, url))
            self.generic_visit(node)

    CallVisitor().visit(tree)
    return calls

def scan_project(root):
    api_calls = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            full_path = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(full_path, root)
            calls = find_api_calls_in_file(full_path)
            if calls:
                api_calls[rel_path] = calls
    return api_calls

def format_output(api_calls):
    lines = ["Gevonden API‑endpoints:\n"]
    for path, calls in sorted(api_calls.items()):
        lines.append(f"🔗 {path}")
        for method, lineno, url in calls:
            lines.append(f"   • requests.{method.upper()} in {path} (regel {lineno}) → {url}")
        lines.append("")
    return "\n".join(lines)

def generate_mermaid(api_calls, mmd_path):
    lines = ["```mermaid", "flowchart LR"]
    node_ctr = 0
    file_id_map = {}

    for path in sorted(api_calls.keys()):
        node_ctr += 1
        fid = f"F{node_ctr}"
        file_id_map[path] = fid
        label = os.path.basename(path)
        lines.append(f"    {fid}(({label}))")

    for path, calls in sorted(api_calls.items()):
        fid = file_id_map[path]
        for method, lineno, url in calls:
            node_ctr += 1
            cid = f"N{node_ctr}"
            safe_url = url.replace('"', '\\"')
            lines.append(f"    {cid}[\"{method.upper()}@{lineno}\\n{safe_url}\"]")
            lines.append(f"    {fid} --> {cid}")

    lines.append("```")
    with open(mmd_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main():
    parser = argparse.ArgumentParser(
        description="Detecteer requests.<method> calls en genereer Mermaid diagram"
    )
    parser.add_argument("root", nargs="?", default=os.getcwd(), help="Root directory van je project (default: huidige map)")
    parser.add_argument("-o", "--output", dest="txt_out", default="api_calls.txt", help="Output tekstbestand")
    parser.add_argument("-m", "--mermaid", dest="mmd_out", default="api_calls.mmd", help="Output Mermaid-bestand")
    args = parser.parse_args()

    api_calls = scan_project(args.root)
    report = format_output(api_calls)

    with open(args.txt_out, "w", encoding="utf-8") as f:
        f.write(report)
    generate_mermaid(api_calls, args.mmd_out)

    print(f"\nAPI‑calls opgeslagen in '{args.txt_out}'")
    print(f"Mermaid diagram opgeslagen in '{args.mmd_out}'\n")
    print(report)

if __name__ == "__main__":
    main()
