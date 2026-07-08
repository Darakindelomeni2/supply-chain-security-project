# Threat model — Chaîne d'approvisionnement logicielle

- **Groupe : 5** — Ella MZOUGHI · Valéry-Alexandre CAMUS  · **Date :** 08/07/2026

> 1-3 pages. Objectif : montrer que vous **raisonnez menaces → contrôles → couverture**,
> pas seulement « on a installé des outils ».

## 1. Actif à protéger

L'artefact (image) qui tourne en production doit être **exactement** celui produit à partir du
code revu, par notre chaîne, sans altération. Propriétés visées : **intégrité**, **authenticité**,
**traçabilité** (provenance).

## 2. Surface & acteurs de menace

- Dépendances tierces (amont) — ex. backdoor XZ.
- Runner / étape de CI compromis — ex. SolarWinds, Codecov.
- Registry compromis / substitution d'image.
- Accès cluster non autorisé (déploiement d'une image pirate).
- Développeur négligent (tag `:latest`, image non signée).

## 3. Table menaces → contrôles → couverture

| # | Menace | Vecteur | Contrôle mis en place | Couverture | Résiduel |
| --- | --- | --- | --- | --- | --- |
| T1 | Artefact altéré après build | substitution registry | signature cosign liée au **digest** + `verifyImages` | Forte | build lui-même |
| T2 | Déploiement non autorisé | accès cluster | admission Kyverno `Enforce` (signature requise) | Forte | RBAC à durcir |
| T3 | Dépendance **vulnérable** (CVE connue) | amont | SBOM (Syft) + gate Grype sur CRITICAL corrigeable | Moyenne | 0-day / CVE non corrigeable |
| T4 | Origine inconnue de l'artefact | absence de traçabilité | attestation de **provenance** (SLSA) exigée | Forte | provenance falsifiable si build non isolé |
| T5 | Substitution silencieuse | tag mutable | interdiction `:latest`, déploiement par digest | Forte | — |
| T6 | Registry pirate / typosquat | image externe | politique registres autorisés | Forte | — |
| T7 | **Runner / étape de CI compromis** | build piégé (SolarWinds, Codecov) | provenance SLSA (build hébergé + signé, L2) ; identité de workflow épinglée | **Partielle** | build non isolé (L3) : un runner compromis produit un artefact **signé valide** |
| T8 | **Dépendance backdoorée** (sans CVE) | amont (XZ Utils, 2024) | SBOM = inventaire/visibilité ; **le scan ne détecte pas une backdoor** | **Faible** | revue de code, 2 mainteneurs, builds reproductibles, pinning + vérif d'intégrité |

**Lecture critique — les deux menaces phares (T7, T8).** Ce sont précisément les attaques que ce
projet vise en priorité (SolarWinds, XZ), et aussi celles que notre chaîne couvre le **moins**. La
cryptographie prouve *qui* a produit l'artefact et *qu'il n'a pas été altéré après coup* — mais
**pas que le build ou le code source était sain**. Un runner compromis (T7) ou un mainteneur
malveillant qui introduit une backdoor (T8) produit un artefact **légitimement signé**, que Kyverno
acceptera. La couverture réelle de T7/T8 passe par des contrôles **hors chaîne cryptographique** :
build isolé (SLSA L3), revue de code obligatoire à plusieurs, builds reproductibles, et surveillance
du journal de transparence **Rekor**. C'est la limite fondamentale à assumer : **notre chaîne
déplace la confiance vers l'identité de build et les humains qui la contrôlent — elle ne l'élimine
pas.**

Les contrôles **T1/T2 (signature), T5 (:latest / digest) et T6 (registry)** sont vérifiés à
l'admission par Kyverno (`Enforce`) et **prouvés à l'acceptation** (image conforme → pods Running,
cf. rapport §3.5). **T3** (SBOM + gate Grype) est prouvé au build (rapport §3.2).

> 🖊️ **[À compléter — Ella, Lab 4]** — Prouver chaque **rejet** en direct : image **non signée**,
> image **modifiée** (digest changé), **:latest**, **registry non autorisé** → capture du message
> Kyverno pour chacun. Ajuster la colonne « Couverture » si un scénario révèle une faille.

## 4. Ce qui reste hors périmètre / non couvert

- Compromission du **build** lui-même (viser SLSA L3 : build isolé).
- Sécurité du poste développeur / des secrets en amont.
- Vulnérabilités **0-day** ou sans correctif disponible.

## 5. Niveau SLSA visé vs atteint

| | Visé | Atteint | Justification |
| --- | --- | --- | --- |
| Provenance existe (L1) | ✅ | ✅ (voie locale) | attestation SLSA signée, attachée à l'image, exigée à l'admission |
| Build hébergé + provenance signée (L2) | ✅ | 🔶 en CI | identité OIDC du workflow GitHub Actions — cf. Lab 5 (Ella) |
| Build isolé infalsifiable (L3) | — | ✗ | hors périmètre du projet |

> 🖊️ **[À confirmer — Ella, Lab 5]** — Une fois la CI en place, basculer L2 de 🔶 à ✅ et
> renseigner l'identité de workflow vérifiée (keyless).
