import os
import subprocess

# Namen van mappen (en bestanden) die we willen overslaan.
IGNORE_LIST = {
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "site-packages",
    "diagram_generator_mermaid",  # Deze map overslaan
}

# Mappen (in lowercase) die we willen groeperen in een subgraph met een specifieke kleur.
GROUPS = {
    "analyzer": "#ffcccc",
    "export": "#ccffcc",
    "filters": "#ccccff",
    "gui": "#ffffcc",
    "heatmap": "#ccffff",
    "ioc": "#ffccff",
    "scheduler": "#e0e0e0",
    "ssh": "#ffedcc",
    "utils": "#edffcc",
}

node_counter = 0

def get_next_node_id():
    global node_counter
    node_counter += 1
    return f"node{node_counter}"

def generate_tree(path, level=0):
    """
    Bouwt een boomstructuur (als geneste dict) op van de mappen/bestanden.
    Items uit IGNORE_LIST en __init__.py worden overgeslagen.
    Verborgen items (die met een punt beginnen) worden overslagen als level > 0.
    """
    basename = os.path.basename(os.path.normpath(path))
    if not basename:
        basename = path

    # Sla over als de naam in IGNORE_LIST zit of als het een verborgen item is (behalve bij de root)
    if basename in IGNORE_LIST or (basename.startswith('.') and level > 0):
        return None

    # Als het een bestand is en __init__.py, overslaan
    if os.path.isfile(path) and basename == "__init__.py":
        return None

    if os.path.isdir(path):
        children = []
        try:
            for entry in sorted(os.listdir(path)):
                full_path = os.path.join(path, entry)
                child = generate_tree(full_path, level + 1)
                if child is not None:
                    children.append(child)
        except Exception as e:
            print(f"Fout bij lezen van {path}: {e}")
            children = []
        return {"name": basename, "type": "dir", "children": children}
    else:
        # Alleen .py-bestanden tonen (anders overslaan)
        if basename.endswith(".py"):
            return {"name": basename, "type": "file"}
        else:
            return None

def tree_to_mermaid(tree, parent_id=None, mermaid_lines=None):
    """
    Converteer de boomstructuur recursief naar Mermaid-code.
    Als een directory op een direct niveau onder de root in GROUPS zit,
    wordt deze als een subgraph met de opgegeven kleur weergegeven.
    """
    if mermaid_lines is None:
        mermaid_lines = []
    current_id = get_next_node_id()

    # Format: directories als cirkel (rond) en bestanden als rechthoek.
    if tree["type"] == "dir":
        node_label = f"(({tree['name']}))"
    else:
        node_label = f"[{tree['name']}]"

    if parent_id is None:
        mermaid_lines.append(f"    {current_id}{node_label}")
    else:
        mermaid_lines.append(f"    {parent_id} --> {current_id}{node_label}")

    # Indien directory: indien op direct niveau en de naam komt overeen met een groep, maak dan een subgraph.
    if tree["type"] == "dir":
        # Bepaal of deze node op direct niveau onder de root staat.
        # (Hier gaan we er vanuit dat als parent_id niet None is én de tree-naam in GROUPS zit, het een subgraph mag zijn.)
        if parent_id is not None and tree["name"].lower() in GROUPS:
            mermaid_lines.append(f"    subgraph {tree['name']}")
            for child in tree.get("children", []):
                tree_to_mermaid(child, current_id, mermaid_lines)
            mermaid_lines.append("    end")
            color = GROUPS[tree["name"].lower()]
            # Opmerking: De 'style'-regel werkt enkel als je de id van de subgraph kent.
            # Omdat subgraph-namen in Mermaid mogelijk niet uniek zijn, is het soms beter om
            # simpelweg in de tekst te vermelden welke kleur hoort bij welke groep.
            mermaid_lines.append(f"    style {current_id} fill:{color},stroke:#333,stroke-width:1px")
        else:
            for child in tree.get("children", []):
                tree_to_mermaid(child, current_id, mermaid_lines)
    return mermaid_lines

def main():
    root_path = r"C:\Users\Devel\Desktop\Security Scanner"
    # Bouw de boomstructuur op.
    tree = generate_tree(root_path)
    mermaid_lines = tree_to_mermaid(tree)
    
    filename = "diagram.mmd"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("```mermaid\n")
        f.write(
            "%%{ init: {'flowchart': {\n"
            "    'rankDir': 'TB',\n"             # Top-down layout
            "    'nodeSpacing': 20,\n"           # Horizontale ruimte tussen nodes
            "    'rankSpacing': 60,\n"           # Verticale ruimte tussen niveaus
            "    'ranker': 'tight-tree'\n"       # Compacte layout
            "} } }%%\n"
        )
        f.write("flowchart TB\n")
        for line in mermaid_lines:
            f.write(line + "\n")
        f.write("```")
    print(f"Mermaid-code opgeslagen in {filename}")

    # Als je direct een afbeelding wilt genereren (vereist mmdc):
    # subprocess.run(["mmdc", "-i", filename, "-o", "diagram.png"], check=True)

if __name__ == "__main__":
    main()