## Presentación: Árbol vs MoE (UNSW-NB15)

### 1) Resumen del dataset

- **Filas**: 175341

- **Columnas**: 45

- **Faltantes (total)**: 0

- **Distribución `label`**: {1: 119341, 0: 56000}

- **Top `attack_cat`**: {'Normal': 56000, 'Generic': 40000, 'Exploits': 33393, 'Fuzzers': 18184, 'DoS': 12264, 'Reconnaissance': 10491, 'Analysis': 2000, 'Backdoor': 1746, 'Shellcode': 1133, 'Worms': 130}

### 2) Modelos comparados y configuración

- **Baseline (DecisionTree)**:

  - Tipo: `sklearn.tree.DecisionTreeClassifier`

  - Objetivo: clasificación **binaria** `label` ∈ {0 (Normal), 1 (Ataque)}

  - Features: todas las columnas del CSV menos `['id', 'attack_cat', 'label', 'mitre', 'id_instancia', 'saddr', 'sport', 'daddr', 'dport', 'stime', 'ltime']` (cuando existen)

  - Configuración principal: `random_state=19`, `max_depth=None` (sin límite explícito)

- **MoE básico (árboles)**:
  - **Gate**:
    - Tipo: `DecisionTreeClassifier`
    - Objetivo: problema **3-clases** {0: Normal, 1: Volumétrico, 2: No-volumétrico}
    - Configuración: `random_state=19`, `max_depth=20`
  - **Expertos (todos `DecisionTreeClassifier`)**:
    - `expert_binary`: entrenado con TODO el dataset (Attack vs Normal)
    - `expert_vol`: entrenado con Normal + ataques volumétricos ['DoS']
    - `expert_nonvol`: entrenado con Normal + ataques no-volumétricos
  - Esquema de inferencia: `gate(x)` selecciona uno de los 3 expertos; ese experto produce la predicción final de ataque (label=1) o normal (label=0).

### 3) Resultados globales (test split)

| model        | accuracy           | precision          | recall             | f1                 |
| ------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| DecisionTree | 0.9476265612227439 | 0.9619513558848197 | 0.9610647152473256 | 0.9615078311653836 |
| MoE_basic    | 0.9487481702564492 | 0.9613187303179779 | 0.9634667485964863 | 0.9623915408866446 |

### 4) Resultado por tipo de ataque (rate de 'predice ataque')

En la siguiente tabla, para cada `attack_cat` se muestra el **porcentaje de flujos donde el modelo predijo ataque (label=1)** en el conjunto de test.
- En la fila `Normal`, este valor se interpreta como una **tasa de falsos positivos aproximada**.

| attack_cat     | baseline_attack_rate | moe_attack_rate |
| -------------- | -------------------- | --------------- |
| Analysis       | 0.939024             | 0.925087        |
| Backdoor       | 0.996183             | 0.986641        |
| DoS            | 0.993367             | 0.98618         |
| Exploits       | 0.983076             | 0.983174        |
| Fuzzers        | 0.795442             | 0.819702        |
| Generic        | 0.999336             | 0.998839        |
| Normal         | 0.081012             | 0.082619        |
| Reconnaissance | 0.993128             | 0.993455        |
| Shellcode      | 0.944606             | 0.93586         |
| Worms          | 1.0                  | 1.0             |

### 5) Nota de interpretación

- Valores cercanos a 1.0 en categorías de ataque indican **alta tasa de detección** (el modelo casi siempre marca ataque).
- Valores cercanos a 0.0 en `Normal` indican **baja tasa de falsas alarmas**.
