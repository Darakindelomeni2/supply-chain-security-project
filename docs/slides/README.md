# Slides d'introduction (Jour 1)

Le PowerPoint est **généré depuis le code** (`generate_slides.py`), pas versionné : le
binaire `.pptx` est régénérable et **ignoré par git** (voir `.gitignore`).

## Régénérer le PowerPoint

```bash
pip install python-pptx
cd docs/slides
python generate_slides.py
# -> intro-supply-chain-security.pptx  (12 slides)
```

## Contenu du deck

1. Titre · 2. Le problème (pipeline digne de confiance ?) · 3. Attaques réelles
(SolarWinds, Codecov, dependency confusion, XZ) · 4. La chaîne vérifiable ·
5. Les 4 briques (SBOM, signature, attestations, admission) · 6. SLSA · 7. Démo cible
attaque/défense · 8. Planning 3 jours · 9. Évaluation · 10. Les 5 labs ·
11. Prérequis & code fourni · 12. À vous de jouer.

> Pour modifier le deck : éditez `generate_slides.py` et relancez. Le style (palette,
> mises en page) est centralisé en haut du script.
