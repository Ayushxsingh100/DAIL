"""Metric extraction (P8b; Doc 13 §25-§35, §32, Appendix B; metrics-draft-1, C-212).

"trial evidence -> metric extractor (versioned) -> metric record -> experiment aggregate" (§32):
``model`` reads the stored trial records into transitions; ``extractor`` turns transitions and the
truth that ``experiments.scoring`` derives into ``MetricRecord``s and the lists of Section 4.
Nothing here reads a label field (``tests/contract/test_experiment_blinding.py``, check (a)).
"""
