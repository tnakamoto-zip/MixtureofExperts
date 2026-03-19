# V3 — Modelos y optimización de hiperparámetros

Resumen de los resultados de optimización de hiperparámetros (`hyperparameters_v3.json`), columnas usadas y proceso de obtención de los modelos.

---

## Resultados (`hyperparameters_v3.json`)

| Dataset       | Modelo     | n_estimators | max_depth | max_leaf_nodes | F1 (CV)   |
|--------------|------------|--------------|-----------|----------------|-----------|
| **v3**       | Binario    | 50           | 6         | —              | **0.9993** |
| **v3**       | Multiclase | 100          | 15        | 50             | **0.9633** |
| **enriched_v3** | Binario | 100          | 12        | 50             | **0.9994** |
| **enriched_v3** | Multiclase | 100       | —         | —              | **0.9884** |

- **Binario**: métrica = F1 (binary). **Multiclase**: métrica = F1 weighted.
- `—` en `max_depth` o `max_leaf_nodes` indica `null` (sin límite en el JSON).

---

## Columnas utilizadas

### Excluidas (no se usan como features)

Se eliminan del entrenamiento:

- `attack_cat` — usada solo como **target** en el modelo multiclase.
- `label` — usada solo como **target** en el modelo binario.
- `mitre`, `id_instancia` — metadatos.
- `saddr`, `sport`, `daddr`, `dport` — identificadores de flujo.
- `stime`, `ltime` — timestamps.

### Codificación one-hot (drop first)

- `proto`, `service`, `state` — se convierten en variables dummy (primera categoría eliminada para evitar multicolinealidad).

### Columnas de entrada (features)

Todas las columnas del CSV que **no** están en la lista de exclusión se usan como variables de entrada. Tras eliminar las anteriores, las features son (entre otras):

- **Flujo/estado**: `num_flows`, `state_rst_ratio`, `state_fin_ratio`, `state_est_ratio`, `rate`, `state`, `proto`, `service`, `dur`.
- **Carga/bytes**: `sload_max`, `dload_max`, `sbytes`, `dbytes`, `sload`, `dload`, `spkts`, `dpkts`.
- **TTL y pérdida**: `sttl`, `dttl`, `sloss`, `dloss`.
- **Ventanas y buffers**: `swin`, `dwin`, `stcpb`, `dtcpb`.
- **Estadísticas de paquetes**: `smean`, `dmean`, `sinpkt`, `dinpkt`, `sintpkt`, `dintpkt`, `smeansz`, `dmeansz`, `sjit`, `djit`.
- **TCP**: `tcprtt`, `synack`, `ackdat`.
- **Conteos/contexto**: `is_sm_ips_ports`, `ct_state_ttl`, `ct_srv_src`, `ct_srv_dst`, `ct_dst_ltm`, `ct_src_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`.

El dataset enriquecido (`dataset_final_enriched_v3.0.csv`) puede incluir columnas adicionales; las mismas reglas se aplican: se excluyen las listadas arriba y se codifican `proto`, `service`, `state`.

---

## Resumen de la obtención de los modelos

1. **Datasets**
   - `dataset_final_v3.0.csv` → clave **v3**.
   - `dataset_final_enriched_v3.0.csv` → clave **enriched_v3**.

2. **Preprocesamiento**
   - Se excluyen filas con `label == 2`.
   - **Binario**: target `label` en {0, 1}. **Multiclase**: target `attack_cat` (se eliminan vacíos y "desconocido").
   - Se eliminan las columnas listadas en “Excluidas” y se construyen las features con el resto.
   - One-hot de `proto`, `service`, `state` (drop first).
   - Imputación: mediana en numéricos, moda en el resto; NaN en categóricos de encoding se rellenan con `'unknown'`.

3. **Entrenamiento y búsqueda**
   - **Algoritmo**: `RandomForestClassifier` (sklearn), `random_state=42`.
   - **Partición**: 70% train / 30% test (`train_test_split`, `random_state=42`).
   - **Validación**: `GridSearchCV` con **5-fold CV**.
   - **Métricas**: F1 para binario, F1 weighted para multiclase.
   - **Grid**: `n_estimators` ∈ {50, 100, 150, 200}, `max_depth` ∈ {6, 7, 8, 9, 10, 12, 15, None}, `max_leaf_nodes` ∈ {None, 50, 100, 200, 500}.
   - Se aplica validación de consistencia entre `max_depth` y `max_leaf_nodes` (y corrección si hace falta).

4. **Salida**
   - Se guardan los mejores hiperparámetros por dataset y tipo de modelo en `hyperparameters_v3.json` para uso en `model.py`.

Script de optimización: `hyperameters.py`.