---
name: neumorphism
description: Soft extruded UI elements with inner and outer shadows for AUDITSCANIA — cybersecurity dashboard with dark navy neumorphism, risk severity colors, and tactile embedded components on Next.js 14 + Tailwind + Radix UI
license: MIT
metadata:
  author: typeui.sh + AUDITSCANIA
---

# Neumorphism Design System — AUDITSCANIA

## Mission
Expert design-system guideline for AUDITSCANIA cybersecurity dashboard.
Dark neumorphism adapté au thème navy avec severity colors et aesthetic Tenable/CrowdStrike.
Chaque composant doit sembler **physiquement ancré** dans la surface sombre — ni plat, ni glassmorphism.

## Brand
AUDITSCANIA — Cybersecurity audit platform. Dark, professional, tactile, data-dense.

---

## Style Foundations

### Typographie
- Primary + Display : `Space Mono` — titres, labels, KPIs
- Mono : `JetBrains Mono` — IPs, IDs, hashes, ports, CVEs
- Weights utilisés : 400, 500, 600, 700
- Règle : toute valeur technique (IP, hash, score) → `font-family: JetBrains Mono`

### Palette de tokens
```
--surface:        #050c18   /* base de tout */
--surface-raised: #0a1628   /* cards, panels surélevés */
--surface-inset:  #030810   /* inputs, gauges enfoncées */
--primary:        #3b82f6   /* glow bleu actif */
--text:           #e2e8f0
--text-muted:     #64748b
--mono-green:     #00ff9f   /* valeurs matrix / terminal */

/* Severity */
--critical:       #ef4444
--high:           #f97316
--medium:         #f59e0b
--low:            #3b82f6
--info:           #64748b
```

### Shadows neumorphiques — Dark Navy
```css
/* Élément surélevé (cards, boutons, widgets) */
.neu-raised {
  box-shadow: 4px 4px 10px #020710, -4px -4px 10px #0c1a30;
}

/* Élément enfoncé (inputs, gauges, zones actives) */
.neu-inset {
  box-shadow: inset 3px 3px 7px #020710, inset -3px -3px 7px #0c1a30;
}

/* Glow bleu — élément actif/focus */
.neu-glow-blue {
  box-shadow: 4px 4px 10px #020710, -4px -4px 10px #0c1a30,
              0 0 14px rgba(59, 130, 246, 0.45);
}

/* Glow rouge — CRITICAL */
.neu-glow-critical {
  box-shadow: 4px 4px 10px #020710, -4px -4px 10px #0c1a30,
              0 0 14px rgba(239, 68, 68, 0.45);
}
```

### Spacing
- Densité : **compact** — dashboard data-dense
- Padding cards : `p-4` (16px)
- Gap grilles : `gap-4`
- Border-radius : `rounded-xl` (12px) pour cards, `rounded-lg` (8px) pour éléments internes

---

## Composants AUDITSCANIA

### KPI Widget
- **Anatomy** : icône Lucide (20px) + label muted + valeur bold Space Mono + badge sévérité
- **Surface** : `--surface-raised` avec `.neu-raised`
- **Hover** : transition vers `.neu-glow-blue`
- **Couleur valeur** : suit la sévérité (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **État loading** : skeleton neumorphique `.neu-inset` animé pulse
- **État erreur** : border `--critical` + glow rouge

```
┌─────────────────────────┐
│  🔴  CRITICAL FINDINGS  │
│       [neu-raised]      │
│  ██  24        +3 ↑     │
└─────────────────────────┘
```

### Risk Gauge SVG
- **Anatomy** : cercle SVG `.neu-inset` + arc coloré + score JetBrains Mono centre
- **Couleur arc** : dynamique selon score
  - 80–100 → `--critical`
  - 60–79  → `--high`
  - 40–59  → `--medium`
  - 20–39  → `--low`
  - 0–19   → `--info`
- **Glow** : arc coloré avec `filter: drop-shadow(0 0 6px <color>)`
- **Animation** : stroke-dashoffset transition 1s ease-out au mount

### ProgressTracker 8 phases
- **Anatomy** : liste verticale de steps connectés par une line
- **Step default** : `.neu-raised` cercle + label Space Mono
- **Step active** : `.neu-glow-blue` + label `--primary`
- **Step complete** : check Lucide vert `#00A63D` + `.neu-inset`
- **Step error** : `.neu-glow-critical` + X Lucide `--critical`
- **Connecteur** : line `--surface-raised`, remplie `--primary` au fur et à mesure

### Tabs Radix UI (12 onglets /scans/[id])
- **Tab inactive** : `.neu-raised` subtle + text `--text-muted`
- **Tab active** : `.neu-inset` + text `--primary` + border-bottom `--primary` 2px
- **Tab hover** : glow bleu léger
- **Scroll** : overflow-x auto sur mobile, wrapping interdit
- **Ordre** : AI Report · ZAP · Nuclei · FFUF · GitLeaks · SQLMap · Nmap · Shodan · VirusTotal · Correlation · FP Filter · AbuseIPDB

### Severity Badge
```
CRITICAL → bg red-950  + text --critical  + border --critical  + glow rouge
HIGH     → bg orange-950 + text --high    + border --high
MEDIUM   → bg amber-950  + text --medium  + border --medium
LOW      → bg blue-950   + text --low     + border --low
INFO     → bg slate-900  + text --info    + border --info
```
- Font : Space Mono, uppercase, text-xs, font-semibold
- Border-radius : `rounded-full`

### Input / Search
- **Surface** : `.neu-inset` sur `--surface-inset`
- **Focus** : ring `--primary` 1px + glow bleu léger
- **Placeholder** : `--text-muted`
- **Icône** : Lucide Search, `--text-muted`

### Boutons
- **Primary** : `.neu-raised` + bg `--primary` → hover `.neu-glow-blue`
- **Secondary** : `.neu-raised` + bg transparent + border `--primary`
- **Danger** : `.neu-raised` + bg `--critical` → hover `.neu-glow-critical`
- **Active/pressed** : switche vers `.neu-inset`
- **Disabled** : opacity-40, shadow supprimée, cursor-not-allowed

### Export Buttons (JSON + PDF)
- Style **Secondary** avec icône Lucide Download
- JSON → icône FileJson, badge `--info`
- PDF → icône FileText, badge `--primary`

### Toast (Sonner)
- Background : `--surface-raised` + `.neu-raised`
- Success : border-left 3px `#00A63D`
- Error : border-left 3px `--critical` + glow rouge
- Warning : border-left 3px `--medium`
- Font : Space Mono text-sm

### Login Page
- **Background** : `--surface` (#050c18) + grid animé CSS (lignes `rgba(59,130,246,0.07)`)
- **Card** : `.neu-raised` centré + glow bleu ambiant
- **Animation grid** : `background-position` translateY en boucle infinie, 20s linear

---

## Règles : Do ✅
- Toujours utiliser les tokens CSS — jamais de hex brut dans les composants
- `.neu-raised` pour les éléments cliquables, `.neu-inset` pour les zones de saisie
- Glow = état actif/focus uniquement — pas décoratif
- JetBrains Mono obligatoire pour toute donnée technique (IP, port, CVE, hash)
- Sévérité = couleur token sémantique (pas de classe Tailwind brute `text-red-500`)
- Transitions : `transition-all duration-200 ease-in-out`

## Règles : Don't ❌
- Pas de fond blanc ou clair — tout sur dark navy
- Pas de shadows portées classiques (box-shadow directionnelle simple) — uniquement neumorphisme bilatéral
- Pas d'élévation glassmorphism (backdrop-blur + transparent) — style différent
- Pas de border-radius > 16px sur les cards principales
- Pas d'animation gratuite — chaque motion doit avoir un sens (état, transition, feedback)
- Pas de `text-red-500` direct — utiliser `text-[var(--critical)]`

---

## Accessibilité WCAG 2.2 AA
- Ratio contraste minimum 4.5:1 pour tout texte sur `--surface`
- Focus visible obligatoire : `focus-visible:ring-2 focus-visible:ring-[var(--primary)]`
- Semantic HTML avant ARIA — utiliser `<nav>`, `<main>`, `<section>` correctement
- Radix UI gère le keyboard navigation — ne pas overrider les handlers par défaut
- `prefers-reduced-motion` : désactiver grid animation et gauge animation

---

## Workflow de génération de composant
1. Identifier la sévérité dominante du composant
2. Choisir `.neu-raised` ou `.neu-inset` selon le rôle
3. Appliquer les tokens couleur sémantiques
4. Ajouter glow uniquement sur état actif/focus/error
5. Typer les valeurs techniques en JetBrains Mono
6. Vérifier le contraste avant de finaliser

---

## QA Checklist
- [ ] Tous les fonds sont sur `--surface` ou dérivés
- [ ] Shadows neumorphiques bilatérales présentes
- [ ] Aucun hex brut dans le JSX/TSX — tokens uniquement
- [ ] JetBrains Mono sur toutes les valeurs techniques
- [ ] Glow uniquement sur états actifs
- [ ] Severity badges avec couleurs sémantiques
- [ ] Focus visible sur tous les éléments interactifs
- [ ] Sonner utilisé pour tous les toasts
- [ ] React Query pour tous les fetches — pas de useEffect fetch
- [ ] TypeScript strict — pas de `any`