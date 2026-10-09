"""The ranking metric vocabulary every analytics view shares (M16.2).

Three endpoints rank something, and all three rank it by the same two metrics, so
the vocabulary is declared once here rather than spelled out per router. The names
are M6's: ``/statistics`` already orders its rankings by ``packets`` or ``bytes``
(M6.5), and reusing that vocabulary is what keeps a client's ``by`` parameter
meaning the same thing wherever it is sent.

The literal type is what makes the guarantee real: a route declares
``by: RankMetric``, so an unknown metric is refused by request validation before a
handler runs, and a query class can accept ``RankMetric`` rather than an
unchecked ``str``.
"""

from __future__ import annotations

from typing import Literal

#: The two metrics an analytics ranking may be ordered by.
RankMetric = Literal["packets", "bytes"]

#: Every accepted value, in the order a help string should list them.
RANK_METRICS: tuple[str, ...] = ("packets", "bytes")

#: The metric a ranking uses when the caller does not name one. Packets, because
#: it is the count that is always present and always comparable; ``bytes`` is a
#: secondary view of the same traffic.
DEFAULT_RANK_METRIC: RankMetric = "packets"

#: Most rows any ranking returns, whatever the caller asks for. Every ranked
#: endpoint caps at this: a ranking is a ranking, and past a hundred rows the
#: answer is a different question — a listing, which already has its own paged
#: endpoint. The cap lives here rather than per query module so the three
#: rankings cannot end up with three different answers to "how long may a
#: ranking be".
MAX_GROUPS = 100


__all__ = ["DEFAULT_RANK_METRIC", "MAX_GROUPS", "RANK_METRICS", "RankMetric"]
