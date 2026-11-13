"""The experiment report (P8b; Doc 13 §33, §35): ``build`` assembles an ExperimentReport from the
extractor's output, ``render`` turns it into Markdown, ``__main__`` is the command line
(``python -m experiments.report``). Nothing here names a label field; trial execution never imports
this package (``tests/contract/test_experiment_blinding.py``).
"""
