"""SQLite persistence adapter behind the Doc 05 §26 repository ports (P1b; C-42 to C-44, C-48).

``schema`` holds the schema-4 DDL and ``initialize_database``; ``sqlite`` holds
``SqliteUnitOfWork``, which implements every port of ``core.domain.repositories`` in one
transaction (Doc 05 §32). The domain never imports this package (rule R1). This package imports
only the standard library and ``core.domain`` (rule R12); ``sqlite3`` is imported here, in
``evidence`` and in ``core.application.health`` only (rule R11).
"""
