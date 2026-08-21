"""
services/intel/
---------------
Cross-module threat-intelligence layer for CYBERSURAKSHAA.

Every detector produces a verdict about one artefact. This package turns those
isolated verdicts into a connected picture:

    indicators.py  — extract atomic indicators (phone, UPI, domain, IP, …)
    graph.py       — persist them as entities + edges, query the neighbourhood
    campaigns.py   — cluster entities into operator-level campaigns
    lookalike.py   — generate and check typosquat / lookalike domains
    evidence.py    — hash-chained, tamper-evident audit log
    multilingual.py— Hinglish / Devanagari normalisation for the keyword banks
    calibration.py — confidence calibration and the abstention band

Nothing in this package imports Flask, so it can be exercised from a plain
Python REPL and from the test-suite without booting the application.
"""
