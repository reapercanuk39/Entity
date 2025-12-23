"""Merge selected package files into a single Queen_merged.py for review.
This script is reversible: it does not modify existing files.
"""
from pathlib import Path
import re

ROOT = Path('.')
order = [
    'Modules/Trait_defs.py',
    'Modules/Traits.py',
    'Modules/Snippets/Base_Broodling.py',
    'Modules/Broodlings.py',
    'Hive/Telemetry.py',
    'Hive/Fitness.py',
    'Hive/Audit.py',
    'Hive/Storage.py',
    'Memory/QueenMemory.py',
    'Policy/Policy.py',
    'Queen.py',
    'Modules/Dashboard.py'
]

files = [ROOT / p for p in order if (ROOT / p).exists()]
if not files:
    print('No files found to merge. Aborting.')
    raise SystemExit(1)

# Collect safe imports (external libs) from all files
import_lines = []
internal_mod_patterns = re.compile(r"(^\s*from\s+\.|^\s*from\s+QueenCore|^\s*from\s+Modules|^\s*from\s+Hive|^\s*from\s+Memory|^\s*from\s+Policy|^\s*from\s+\.\w+)")
for f in files:
    txt = f.read_text(encoding='utf-8')
    for line in txt.splitlines():
        if line.strip().startswith('#'):
            continue
        if line.strip().startswith('import') or line.strip().startswith('from'):
            if internal_mod_patterns.search(line):
                continue
            if line not in import_lines:
                import_lines.append(line)

merged = []
merged.append('# Auto-generated merged file: Queen_merged.py')
merged.append('# Backup branch: ' + "$BRANCH")
merged.append('\n')
# Add imports
merged.extend(import_lines)
merged.append('\n')

# Function to strip internal import lines and adjust common relative imports
strip_patterns = [re.compile(r'^\s*from\s+\.[\w._]+\s+import.*$'),
                  re.compile(r'^\s*from\s+QueenCore[.\w_]*\s+import.*$'),
                  re.compile(r'^\s*from\s+Modules[.\w_]*\s+import.*$'),
                  re.compile(r'^\s*from\s+Hive[.\w_]*\s+import.*$'),
                  re.compile(r'^\s*from\s+Memory[.\w_]*\s+import.*$'),
                  re.compile(r'^\s*from\s+Policy[.\w_]*\s+import.*$')]

for f in files:
    merged.append('\n# --- Begin: ' + str(f) + ' ---\n')
    txt = f.read_text(encoding='utf-8')
    out_lines = []
    skip_block = False
    for line in txt.splitlines():
        # Remove internal import lines
        if any(p.search(line) for p in strip_patterns):
            continue
        # Remove "if __name__ == '__main__'" execution blocks conservatively
        if line.strip().startswith("if __name__"):
            skip_block = True
            continue
        if skip_block:
            if line.startswith(''):
                # continue skipping until block ends heuristically (blank line)
                continue
        out_lines.append(line)
    merged.extend(out_lines)
    merged.append('\n# --- End: ' + str(f) + ' ---\n')

out_path = Path('Queen_merged.py')
out_path.write_text('\n'.join(merged), encoding='utf-8')
print('Wrote', out_path)

# Syntax check
import py_compile
try:
    py_compile.compile(str(out_path), doraise=True)
    print('Syntax check passed for Queen_merged.py')
except py_compile.PyCompileError as e:
    print('Syntax error in merged file:', e)
    raise

# Attempt a guarded import using importlib
import importlib.util, sys
spec = importlib.util.spec_from_file_location('Queen_merged', str(out_path))
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    print('Imported Queen_merged module successfully (executed top-level definitions)')
except Exception as e:
    print('Importing Queen_merged raised an exception (this may be due to top-level code execution):', e)
    # still allow inspection of the file

print('\nMerge complete. Review Queen_merged.py; originals left intact. To apply replace Queen.py with the merged file once validated.')
