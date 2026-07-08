# Notes de passation — pour Ella (Labs 4 & 5)

> J'ai fait les **Labs 0→3** : le POC tourne (image signée + provenance **acceptée** par
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

## Ce qui est déjà fait (partagé) vs à refaire chez toi

**Partagé (rien à refaire) :**

- **Image signée** (cosign v2, tag-based) sur GHCR — tu la **réutilises**, tu ne re-signes pas :
  `ghcr.io/darakindelomeni2/scs-demo-app@sha256:691565737b2dc1bf1d3eecce28a04d8cdc6e467c0092aeeb74fade1cef95c719`
- `cosign.pub` + les 4 policies (avec la clé publique dedans) sont dans le repo.
- `cosign.key` reste le secret **local de mon PC** — **pas nécessaire pour le Lab 4** (tu ne signes
  rien, tu déploies l'image existante + tu déploies des images pirates pour voir les rejets).

**À refaire sur TA machine — le cluster `kind` est local, il ne « tourne » pas chez toi :**

```bash
# 0. outils : docker, kind, kubectl, jq + cosign v2.4.1 (PAS latest/v3 !)
# 1. cluster + Kyverno + namespace
kind create cluster --name scs --config cluster/kind-config.yaml
kubectl create -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml
kubectl -n kyverno rollout status deploy/kyverno-admission-controller
kubectl create namespace app
# 2. TON secret registre (ton PAT read:packages perso) dans les 2 namespaces
kubectl create secret docker-registry ghcr-creds -n app     --docker-server=ghcr.io --docker-username=<ton-user> --docker-password="$GHCR_RO"
kubectl create secret docker-registry ghcr-creds -n kyverno --docker-server=ghcr.io --docker-username=<ton-user> --docker-password="$GHCR_RO"
# 3. politiques + déploiement de l'image DÉJÀ signée
kubectl apply -f policies/kyverno/
kubectl apply -n app -f k8s/deployment.yaml    # doit être ACCEPTÉ (pods Running)
```

> ✅ **Accès au package** : tu es déjà **admin sur le package GHCR** `scs-demo-app` → tu peux le
> pull. Il te faut juste **ton PAT `read:packages`** perso pour créer le secret `ghcr-creds`
> (étape 2 ci-dessus). Le package reste **privé** (choix DevSecOps).

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
