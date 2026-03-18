# Análisis Teórico del Modelo Mixture of Experts (MoE)

Este documento analiza la implementación de la arquitectura Mixture of Experts (MoE) presente en `MoE/UNSW 09.03/unsw_characterize_and_moe.py`, contrastando sus bloques de código con los fundamentos teóricos detallados en los papers de la carpeta `Lectura/` (tales como el seminal "Hierarchical Mixtures of Experts" de Jordan 1994, la revisión "Twenty Years of Mixture of Experts" de Yuksel 2012, y el "Comprehensive Survey of Mixture-of-Experts" de 2026).

---

## 1. Topología del MoE: Gate y Expertos Locales

**Fundamento Teórico:**
Desde el paradigma original presentado en **Jordan y Jacobs (1994)** y expandido en **Yuksel et al. (2012)**, un sistema MoE se apoya en la estrategia de *Divide y Vencerás*. El problema complejo se divide en subregiones del espacio de datos, las cuales son resueltas de manera local mediante "Expertos" especializados (Expert Networks). En paralelo, una compuerta o "Gating Network" (el Router) decide estadísticamente qué experto es más competente para una entrada dada.

**Implementación en Código:**
En el script, esta topología se construye de la siguiente manera:

```python
# Gate (Router - 3 clases)
gate = DecisionTreeClassifier(random_state=random_state, max_depth=20)
gate.fit(X_tr, gate_y_tr)

# Expertos
expert_binary = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr, y_tr)
# (expert_vol y expert_nonvol se inicializan de forma análoga...)
```

**Análisis de la Implementación:**
A diferencia del uso clásico de Redes Neuronales multicapa o modelos lineales para optimización continua, esta implementación utiliza **Árboles de Decisión (`DecisionTreeClassifier`)** tanto para la compuerta como para los expertos. Si bien restringe el entrenamiento end-to-end con backpropagation global continuo (común en LLMs detallados en el Survey 2026), aporta una interpretabilidad inmediata al ser modelos probabilistas discretos. El Gate ejerce el papel real de enrutador multidimensional.

---

## 2. Especialización de los Expertos: *A Priori* vs *Latente*

**Fundamento Teórico:**
Tradicionalmente (Jordan 1994), los expertos son inicializados ciegamente y compiten entre ellos durante cada epoch de entrenamiento usando el algoritmo Expectation-Maximization (EM) o funciones de pérdida de gradiente acopladas. Su especialización ocurre *a posteriori* de manera latente en distribuciones competitivas. Sin embargo, en sistemas reales (y para prevenir un colapso de enrutamiento destacado en el Survey 2026), se suelen utilizar penalizaciones o segmentación de dominio para forzar a cada experto a acaparar una parte de la distribución de features.

**Implementación en Código:**
```python
# Subconjuntos para expertos vol/no-vol definiendo máscaras según conocimiento previo
is_normal_tr = label_raw_tr == 0
is_vol_tr = np.isin(attack_cat_raw_tr, volumetric_attack_cats) & (~is_normal_tr)
is_nonvol_tr = (~np.isin(attack_cat_raw_tr, volumetric_attack_cats)) & (~is_normal_tr)

vol_mask = is_normal_tr | is_vol_tr
nonvol_mask = is_normal_tr | is_nonvol_tr

expert_vol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr[vol_mask], y_tr[vol_mask])
expert_nonvol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr[nonvol_mask], y_tr[nonvol_mask])
```

**Análisis de la Implementación:**
En lugar del algoritmo EM clásico de auto-enrutamiento latente, el código impone un **enrutamiento lógico por dominio (Domain-based explicit routing)**. Un experto es forzado a aprender exclusivamente a distinguir tráfico Normal frente a los ataques "Volumétricos" (`expert_vol`), mientras el otro distingue Normal frente a los "No-Volumétricos" (`expert_nonvol`). Esta división heurística *a priori* previene problemas de convergencia, y obliga a que las representaciones abstractas de los árboles se enfoquen en su dominio objetivo, lo cual es vital para capturar los patrones diferenciados del dataset UNSW-NB15.

---

## 3. Entrenamiento Supervisado del Gating Network

**Fundamento Teórico:**
El **Survey MoE 2026** resalta que la red router (Gating) necesita una política de regularización estricta (o de load-balancing). Dado que aquí no se entrenan por gradientes estocásticos conjuntos, la creación de la compuerta necesita targets "fabricados" para emular qué experto debería haber elegido.

**Implementación en Código:**
```python
def make_gate_target_groups(df_total_raw: pd.DataFrame, volumetric_attack_cats: List[str]) -> np.ndarray:
    # 0 = Normal, 1 = Volumétrico, 2 = No-volumétrico
    is_normal = (df_total_raw["label"].astype(int) == 0) | (df_total_raw["attack_cat"].astype(str) == "Normal")
    gate_y = np.full(shape=(df_total_raw.shape[0],), fill_value=2, dtype=int) 
    gate_y[is_normal.values] = 0
    
    is_vol = df_total_raw["attack_cat"].astype(str).isin(volumetric_attack_cats).values
    gate_y[is_vol & (~is_normal.values)] = 1
    return gate_y
```

**Análisis de la Implementación:**
Para solventar el problema de entrenar al Router de forma matemática e independiente (desacoplado de los expertos), el bloque de código sintetiza perfiles estructurados (`gate_y`). De esta forma, el Router convierte el problema de "routing" en un un clásico problema de **Clasificación Supervisada (Multiclase)**. El router aprende las características macro del perfil de un ataque (ej. conteo de paquetes altísimo vs varianza de bytes).

---

## 4. Inferencia Dinámica: "Sparse/Hard Routing" vs "Soft Routing"

**Fundamento Teórico:**
Por su parte, el paradigma basal de **Jordan (1994)** estandarizó el uso de **Soft Routing**, donde la salida final es un promedio ponderado sumando las probabilidades de la inferencia de *todos* los expertos ($Y = \sum g_i * Y_i$). Por otra parte, la arquitectura moderna de última generación mencionada en el **Survey de MoE de 2026** (como Mixtral y Switch Transformers) prefiere rotundamente **Sparse Routing (o Hard Routing, Top-K, comúnmente con K=1 o K=2)**, para mitigar cuellos de botella y costos computacionales (Sparsity). 

**Implementación en Código:**
```python
def predict_basic_moe(moe: MoEModels, X: np.ndarray) -> np.ndarray:
    # Gate actua como argmax hard-router
    gate_pred = moe.gate.predict(X)  # 0 normal, 1 vol, 2 nonvol
    y_pred = np.zeros(shape=(X.shape[0],), dtype=int)

    idx_normal = np.where(gate_pred == 0)[0]
    idx_vol = np.where(gate_pred == 1)[0]
    idx_nonvol = np.where(gate_pred == 2)[0]

    # Inferencia puramente individual k=1 (Hard Routing)
    if idx_normal.size > 0:
        y_pred[idx_normal] = moe.expert_binary.predict(X[idx_normal])
    if idx_vol.size > 0:
        y_pred[idx_vol] = moe.expert_vol.predict(X[idx_vol])
    if idx_nonvol.size > 0:
        y_pred[idx_nonvol] = moe.expert_nonvol.predict(X[idx_nonvol])

    return y_pred
```

**Análisis de la Implementación:**
La formulación en `predict_basic_moe` materializa de manera exacta el concepto contemporáneo de **Sparse Hard Routing (k=1)**. La decisión de la compuerta no da una ponderación suave (soft probability mass), sino que elige activamente UN único camino de ejecución, obviando los otros 2 subárboles. Es decir, a nivel computacional, para clasificar 1 registro concreto `x`, si el Gating dicta clase `1`, la información irá **solo** al `expert_vol`. Esto es ideal en el mundo de los NIDS o HIDS (Sistemas de Intrusión), pues garantiza baja latencia computacional. Adicionalmente, el `expert_binary` funge como experto fallback/generalista de salvaguarda ante flujos nominales.

> **Conclusión**
> El archivo `unsw_characterize_and_moe.py` exhibe un acercamiento pragmático, modular e interpretable. Evita las complejidades matemáticas acopladas al EM/Backpropagation estocástico propuesto por Jordan(1994), sustituyéndolas por subconjuntos discretos a priori, y capitaliza sobre el concepto de Hard Sparse Routing altamente promovido por el Survey del 2026, asegurando así un MoE excepcionalmente rápido y enfocado en subpatrones explícitos de la capa red (volumétrico vs no-volumétrico).
