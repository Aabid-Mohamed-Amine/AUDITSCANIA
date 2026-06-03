"""
False Positive Reduction Engine v2 — Classification par tiers.

Principe : aucun finding n'est supprimé, chaque finding est classé :
  confirmed     → haute confiance, prêt pour le rapport
  suspicious    → confiance moyenne, à investiguer
  informational → faible confiance, gardé pour référence

Règles never-delete :
  - CRITICAL → toujours ≥ suspicious
  - CVE avec ID → toujours ≥ suspicious
  - Exposures → toujours confirmed
  - Multi-source → toujours ≥ suspicious
"""
from .reducer import reduce_false_positives

__all__ = ["reduce_false_positives"]
