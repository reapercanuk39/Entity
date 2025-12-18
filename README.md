# QueenCore 🐝

**Digital life engine** — QueenCore is a config‑driven orchestration system where the Queen manages broodlings, traits, and lineage in real time. Every module is designed for resilience, adaptability, and future‑proof evolution.

## Features
- Config‑driven orchestration: hatch broodlings with roles, traits, caps, and stage directly from config.
- Adaptive telemetry: turn error logs into actionable signals for simulation adaptation.
- Role‑based trait inheritance: broodlings evolve with lineage and fusion logic.
- Modular architecture: clear boundaries across Hive, Memory, Modules, and Policy layers.

## File Structure
- `QueenCore/Config` → central configuration JSON
- `QueenCore/Hive` → orchestration, telemetry, storage, audit
- `QueenCore/Memory` → genetic memory and persistence
- `QueenCore/Modules` → broodlings, traits, dashboard, snippets
- `QueenCore/Policy` → adaptive policy engine
- `QueenCore/Queen.py` → main entry point

## Getting Started
Clone the repo:
```bash
git clone git@github.com:reapercanuk39/QueenCore.git
cd QueenCore
