# Notes de passation — pour Ella (Labs 4 & 5)

> Valéry a fait les **Labs 0→3** : le POC tourne (image signée + provenance **acceptée** par
> Kyverno, pods `Running`). Rapport §1-7 + annexes + threat model rédigés. Il te reste **Lab 4**
> (démo attaque/défense) et **Lab 5** (CI), + quelques cases dans les livrables.

## ⚠️ À LIRE EN PREMIER — le piège qui a coûté une soirée

**cosign v3 (le `latest`) est incompatible avec Kyverno** : il stocke les signatures via l'API OCI
1.1 referrers, que Kyverno ne sait pas lire → images **rejetées à tort** (`no signatures found`).

- **En local** : on a épinglé **cosign v2.4.1** (`~/.local/bin/cosign`). Vérifie : `cosign version` → v2.4.1.
- **En CI (Lab 5)** : le workflow **doit** utiliser **cosign v2** pour `sign`/`attest`
  (pas l'action par défaut qui tire v3), sinon Kyverno rejettera pareil.
- **SBOM** : générer en **package-level** (léger, < 2 Mi), sinon la limite `maxContextSize` de Kyverno
  bloque la vérif d'attestation :
  `syft "$IMG:$TAG" -o spdx-json | jq 'del(.files, .relationships)' > sbom.spdx.json`
  (avec un SBOM léger, **aucun patch Kyverno n'est nécessaire**.)

## État actuel (déjà en place)

- **Image signée** : `ghcr.io/darakindelomeni2/scs-demo-app@sha256:691565737b2dc1bf1d3eecce28a04d8cdc6e467c0092aeeb74fade1cef95c719`
- **Cluster** : `kind` (`scs`) + Kyverno v1.18, 4 `ClusterPolicy` en `Enforce` (`kubectl get clusterpolicy`).
- **Registry privé** : secrets `ghcr-creds` dans les namespaces `app` et `kyverno` (PAT `read:packages`).
- **Clé de signature** : `cosign.pub` (publique, dans le repo) ; `cosign.key` **jamais commité**
  (demande le mot de passe à Valéry pour re-signer si besoin).

## Ta TODO

**Lab 4 — démo attaque/défense** (le cœur de ta partie) :
- [ ] Déployer une image **non signée** (ex. `kubectl -n app run pirate --image=nginx:latest`) → **rejet** Kyverno, capturer le message.
- [ ] Image **modifiée après signature** (digest changé) → rejet.
- [ ] `:latest` et **registry non autorisé** → rejet.
- [ ] Rappeler que l'image **légitime** est acceptée (déjà prouvé §3.5).
- [ ] Captures dans `livrables/assets/lab4-*.png` + (conseillé) une **vidéo** de la démo (plan B).

**Lab 5 — CI GitHub Actions** (bonus) : build→sbom→scan→**sign (cosign v2)**→attest→push, en keyless
si possible (identité OIDC du workflow). Voir `.github/workflows/supply-chain.yml` (à adapter : cosign v2 + SBOM léger).

**Livrables — cherche les marqueurs `🖊️` dans `livrables/` :**
- [ ] `rapport-groupe5.md` §4 (démo), §7 (ta ligne de répartition), annexe C (message de refus).
- [ ] `threat-model-groupe5.md` §3 (prouver les rejets), §5 (passer L2 🔶→✅ après la CI).

## Commandes utiles

```bash
# ré-exporter les variables dans un nouveau terminal
export IMG=ghcr.io/darakindelomeni2/scs-demo-app
export TAG=0.1.0
export DIGEST="ghcr.io/darakindelomeni2/scs-demo-app@sha256:691565737b2dc1bf1d3eecce28a04d8cdc6e467c0092aeeb74fade1cef95c719"

kubectl get clusterpolicy          # 4 × READY=true
kubectl get pods -n app            # image légitime : Running
```
