"""HCL native syntax: lexer, parser and immutable syntax tree (Doc 04 §4; C-91).

Pure standard library. ``parse_file`` is the entry point; the modules ``ast``, ``lexer`` and
``errors`` hold the tree, the tokens and the internal errors.
"""
