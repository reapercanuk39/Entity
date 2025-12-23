from pathlib import Path
import re
ROOT=Path('.')
order = [
    'Modules/Trait_defs.py',
    'Modules/Traits.py',
    'Modules/Snippets/Base_Broodling.py',
    'Hive/Audit.py',
    'Modules/Broodlings.py',
    'Hive/Telemetry.py',
    'Hive/Fitness.py',
    'Hive/Storage.py',
    'Memory/QueenMemory.py',
    'Policy/Policy.py',
    'Queen.py',
    'Modules/Dashboard.py'
]
files=[ROOT/p for p in order if (ROOT/p).exists()]
if not files:
    print('No files to merge in specified order'); raise SystemExit(1)
# collect external imports
import_lines=[]
internal_mod_patterns = re.compile(r"^\s*(from\s+(?:\.|QueenCore|Modules|Hive|Memory|Policy|queen|Modules)\b|from\s+queen\.modules\b|from\s+queen\.|from\s+Modules\.|from\s+Hive\.|from\s+Memory\.|from\s+Policy\.)")
for f in files:
    txt=f.read_text(encoding='utf-8')
    for line in txt.splitlines():
        s=line.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('import ') or s.startswith('from '):
            if internal_mod_patterns.search(line):
                continue
            if line not in import_lines:
                import_lines.append(line)
# build merged content
parts=[]
parts.append('# Auto-generated merged file (regenerated)')
parts.append('\n')
parts.extend(import_lines)
parts.append('\n')
strip_patterns=[re.compile(r'^\s*from\s+\.'), re.compile(r'^\s*from\s+QueenCore'), re.compile(r'^\s*from\s+Modules'), re.compile(r'^\s*from\s+Hive'), re.compile(r'^\s*from\s+Memory'), re.compile(r'^\s*from\s+Policy'), re.compile(r'^\s*from\s+queen')]
for f in files:
    parts.append('\n# --- Begin: ' + str(f) + ' ---\n')
    txt=f.read_text(encoding='utf-8')
    out=[]
    skip_block=False
    for line in txt.splitlines():
        if any(p.search(line) for p in strip_patterns):
            continue
        if line.strip().startswith('if __name__'):
            skip_block=True
            continue
        if skip_block:
            # stop skipping when encounter a blank line (heuristic)
            if line.strip()=='':
                skip_block=False
            continue
        out.append(line)
    parts.extend(out)
    parts.append('\n# --- End: ' + str(f) + ' ---\n')
out_path=Path('Queen_merged.py')
out_path.write_text('\n'.join(parts), encoding='utf-8')
print('Wrote', out_path)
