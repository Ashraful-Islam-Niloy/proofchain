# ProofChain

A GUI workspace for ethical hackers to **validate findings with evidence**
and **detect exploit chains** before reporting.

Scanners find. Reporters format. ProofChain sits in the gap between them —
the human judgment layer that decides what's real and how findings combine.

## Why

The 2026 pentest landscape is drowning in findings. AI agents and scanners
produce volume; the bottleneck has shifted from *discovery* to
**verification**. ProofChain enforces a rule no scanner can: a finding cannot
be marked *validated* until a human attaches evidence. Chains only become
*confirmed* when you've linked them and explained how they combine.

## Install & run

```bash
pip install -r requirements.txt
python main.py
