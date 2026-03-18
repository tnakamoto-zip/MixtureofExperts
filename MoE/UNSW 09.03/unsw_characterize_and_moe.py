"""
Caracterización + Baseline (Árbol) + MoE básico para UNSW-NB15.

Objetivo (según lo solicitado):
- Caracterizar el dataset (resúmenes y distribuciones).
- Entrenar:
  1) Árbol de decisión binario Attack vs Normal (baseline)
  2) MoE *muy básico* con árboles:
        - Experto binario (Attack vs Normal)
        - Experto volumétrico (Attack vs Normal, entrenado en DoS + Normal)
        - Experto no-volumétrico (Attack vs Normal, entrenado en no-DoS + Normal)
     y un GATE (árbol) que decide qué experto usar.
- Generar una "presentación" (Markdown) con tablas:
  - métricas globales Árbol vs MoE
  - desempeño por tipo de ataque (attack_cat)

Notas importantes:
- Se inspira en el flujo del notebook `SHAP_UNSW_NB15.ipynb` (LabelEncoder + drop de columnas).
- Diseñado para Python 3.9 (sin type unions con |).

Cómo leer este archivo (estructura):
- Sección 1: "caracterización" = describir el dataset antes de modelar.
- Sección 2: preprocesado estilo notebook (LabelEncoder + construcción de X/y).
- Sección 3: modelos:
    - Baseline: un árbol binario Attack vs Normal.
    - MoE básico: un "gate" (árbol multiclase) + 3 expertos (árboles binarios).
- Sección 4: métricas y reportes (global y por `attack_cat`).
- Sección 5: main: ejecuta todo y guarda outputs (csv/pkl/md/json).

Relación con `Documentacion_modelos.md`:
- Allí se documenta el pipeline "grande" de producción (datasets `v3` / `enriched_v3` con RandomForest + GridSearch):
  - **Columnas excluidas**: `attack_cat`, `label`, `mitre`, `id_instancia`, 
                            `saddr`, `sport`, `daddr`, `dport`,`stime`, `ltime`.

  - **Codificación**: one-hot (dummies) para `proto`, `service`, `state` con "drop first".
  - **Columnas de entrada**: todas las columnas que no estén en la lista de exclusión.
  - **Entrenamiento**: RandomForest + GridSearchCV (5-fold) con F1 como métrica principal.
- En este archivo hacemos una **versión reducida** específicamente para el notebook de UNSW:
  - seguimos la lógica del notebook (LabelEncoder + drop de `id`, `attack_cat`, `label`);
  - añadimos la lista de exclusión del documento cuando esas columnas están presentes,
    para que el comportamiento sea coherente si se aplica a un dataset enriquecido;
  - usamos árboles de decisión simples (no RandomForest) para que el MoE sea fácil de explicar y modificar.
"""

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier


# -------------------------
# 1) Caracterización dataset
# -------------------------


def characterize_dataset(df: pd.DataFrame) -> Dict[str, Any]:
    # Esta función produce un "resumen ejecutivo" del dataset para reportarlo en una presentación.
    # No cambia datos: sólo cuenta, describe y calcula distribuciones.
    info: Dict[str, Any] = {}

    info["n_rows"] = int(df.shape[0])
    info["n_cols"] = int(df.shape[1])
    info["columns"] = df.columns.tolist()

    # Missing values: si hubiera, aquí aparecen por columna.
    na_counts = df.isna().sum().sort_values(ascending=False)
    info["missing_total"] = int(na_counts.sum())
    info["missing_by_column_top"] = na_counts.head(15).to_dict()

    # Distribuciones del objetivo:
    # - `label`: 0 normal, 1 ataque (binario)
    # - `attack_cat`: tipo de ataque (multiclase)
    if "label" in df.columns:
        info["label_counts"] = df["label"].value_counts(dropna=False).to_dict()
        # porcentaje
        vc = df["label"].value_counts(dropna=False)
        info["label_pct"] = (vc / vc.sum() * 100.0).round(4).to_dict()

    if "attack_cat" in df.columns:
        ac = df["attack_cat"].value_counts(dropna=False)
        info["attack_cat_counts"] = ac.to_dict()
        info["attack_cat_pct"] = (ac / ac.sum() * 100.0).round(4).to_dict()

    # Tipos de columnas
    info["dtypes"] = {c: str(t) for c, t in df.dtypes.to_dict().items()}

    return info


def save_characterization(out_path: str, characterization: Dict[str, Any]) -> None:
    # Guardamos la caracterización en JSON para reproducibilidad y para adjuntarlo a reportes.
    Path(out_path).write_text(json.dumps(characterization, indent=2, ensure_ascii=False), encoding="utf-8")


# -------------------------
# 2) Preprocesado (estilo notebook)
# -------------------------


@dataclass
class Encoders:
    LE_proto: LabelEncoder
    LE_service: LabelEncoder
    LE_state: LabelEncoder
    LE_attack_cat: LabelEncoder
    LE_label: LabelEncoder


def fit_encoders(df: pd.DataFrame) -> Encoders:
    # En el notebook se usan LabelEncoders para convertir texto -> entero en:
    # proto, service, state, attack_cat y label.
    LE_proto = LabelEncoder()
    LE_service = LabelEncoder()
    LE_state = LabelEncoder()
    LE_attack_cat = LabelEncoder()
    LE_label = LabelEncoder()

    LE_proto.fit(df["proto"])
    LE_service.fit(df["service"])
    LE_state.fit(df["state"])
    LE_attack_cat.fit(df["attack_cat"])
    LE_label.fit(df["label"])

    return Encoders(
        LE_proto=LE_proto,
        LE_service=LE_service,
        LE_state=LE_state,
        LE_attack_cat=LE_attack_cat,
        LE_label=LE_label,
    )


def apply_encoders_notebook_style(df_total: pd.DataFrame, enc: Encoders) -> pd.DataFrame:
    # Misma idea del notebook:
    # - Copiamos el DF para no mutarlo.
    # - Transformamos las columnas categóricas con los encoders ya entrenados.
    df_attack = df_total.copy()

    df_attack["proto"] = enc.LE_proto.transform(df_attack["proto"])
    df_attack["service"] = enc.LE_service.transform(df_attack["service"])
    df_attack["state"] = enc.LE_state.transform(df_attack["state"])
    df_attack["attack_cat"] = enc.LE_attack_cat.transform(df_attack["attack_cat"])
    df_attack["label"] = enc.LE_label.transform(df_attack["label"])

    return df_attack


def make_xy_binary(df_attack_encoded: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    # Construcción de X/y para el problema binario "Attack vs Normal".
    # Igual que el notebook:
    # - y_total = label
    # - X = todo menos ['id', 'attack_cat', 'label']
    #
    # Además incorporamos las **consideraciones de exclusión** de `Documentacion_modelos.md`:
    # - `mitre`, `id_instancia` → metadatos
    # - `saddr`, `sport`, `daddr`, `dport` → identificadores de flujo
    # - `stime`, `ltime` → timestamps
    # Si esas columnas existen en el DF, también se eliminan de X.
    # (En el UNSW "crudo" no aparecen, pero sí en datasets enriquecidos.)
    y_total = df_attack_encoded["label"].to_numpy()

    base_excluded = ["id", "attack_cat", "label"]
    extra_excluded = ["mitre", "id_instancia", "saddr", "sport", "daddr", "dport", "stime", "ltime"]
    cols_to_drop = [c for c in base_excluded + extra_excluded if c in df_attack_encoded.columns]

    X_df = df_attack_encoded.drop(cols_to_drop, axis=1)
    X_total = X_df.values
    feature_names = X_df.columns.tolist()

    return X_total, y_total, feature_names


def make_gate_target_groups(
    df_total_raw: pd.DataFrame,
    volumetric_attack_cats: List[str],
) -> np.ndarray:
    """
    Gate target (3 clases):
    - 0: normal
    - 1: volumétrico
    - 2: no-volumétrico

    Definición mínima del gate (muy simple, pero funcional):
    - Normal si label==0 o attack_cat == 'Normal'
    - Volumétrico si attack_cat está en volumetric_attack_cats (por defecto: ['DoS'])
    - Resto de ataques -> no-volumétrico
    """

    # Normalidad: en UNSW típicamente label=0 equivale a Normal (attack_cat=Normal)
    is_normal = (df_total_raw["label"].astype(int) == 0) | (df_total_raw["attack_cat"].astype(str) == "Normal")
    gate_y = np.full(shape=(df_total_raw.shape[0],), fill_value=2, dtype=int)  # no-vol por defecto
    gate_y[is_normal.values] = 0

    is_vol = df_total_raw["attack_cat"].astype(str).isin(volumetric_attack_cats).values
    gate_y[is_vol & (~is_normal.values)] = 1
    return gate_y


# -------------------------
# 3) Modelos: Árbol baseline + MoE básico
# -------------------------


def train_decision_tree_binary(X_tr: np.ndarray, y_tr: np.ndarray, random_state: int = 19) -> DecisionTreeClassifier:
    # Baseline del notebook:
    # Un único árbol de decisión que aprende reglas "if feature <= threshold" para predecir label (0/1).
    # En la documentación general (`Documentacion_modelos.md`) el modelo de producción es un RandomForest
    # optimizado con GridSearchCV; aquí usamos un solo árbol para:
    # - mantener interpretabilidad (similar a lo que se visualiza con SHAP);
    # - simplificar el anidamiento dentro del MoE (gate + expertos).
    clf = DecisionTreeClassifier(random_state=random_state)
    return clf.fit(X_tr, y_tr)


@dataclass
class MoEModels:
    gate: DecisionTreeClassifier
    expert_binary: DecisionTreeClassifier
    expert_vol: DecisionTreeClassifier
    expert_nonvol: DecisionTreeClassifier
    volumetric_attack_cats: List[str]


def train_basic_moe(
    df_total_raw: pd.DataFrame,
    df_attack_encoded: pd.DataFrame,
    X_all: np.ndarray,
    y_all: np.ndarray,
    *,
    feature_names: List[str],
    volumetric_attack_cats: List[str],
    test_size: float = 0.30,
    random_state: int = 19,
) -> Tuple[MoEModels, Dict[str, Any]]:
    """
    Entrenamiento MoE básico:
    - Gate: un árbol multiclase que predice a qué "región" pertenece una instancia:
        {normal, volumétrico, no-volumétrico}.
      El objetivo del gate NO es predecir ataque, sino seleccionar el experto más adecuado.

    - Expertos: 3 árboles binarios distintos (todos predicen label 0/1):
        - expert_binary: entrenado con TODO (sirve como fallback y experto generalista).
        - expert_vol: entrenado con (Normal + ataques volumétricos) para especializarse en esos patrones.
        - expert_nonvol: entrenado con (Normal + ataques no-volumétricos) para especializarse en el resto.

    En inferencia (predicción):
    1) gate(x) -> {0,1,2}
    2) si gate=0 -> expert_binary(x)
       si gate=1 -> expert_vol(x)
       si gate=2 -> expert_nonvol(x)
    """

    # Split para evaluación consistente (baseline y MoE deben evaluarse en test).
    # Se mantiene `stratify=y_all` para conservar proporción de ataques vs normales.
    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X_all,
        y_all,
        np.arange(X_all.shape[0]),
        test_size=test_size,
        random_state=random_state,
        stratify=y_all,
    )

    gate_y_all = make_gate_target_groups(df_total_raw, volumetric_attack_cats)
    gate_y_tr = gate_y_all[idx_tr]
    gate_y_te = gate_y_all[idx_te]

    # Gate (3 clases). `max_depth` moderado para evitar árboles infinitos.
    gate = DecisionTreeClassifier(random_state=random_state, max_depth=20)
    gate.fit(X_tr, gate_y_tr)

    # Expertos: cada experto es un árbol binario independiente.
    expert_binary = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr, y_tr)

    # Subconjuntos para expertos vol/no-vol (usamos attack_cat/label "raw" para construir máscaras).
    attack_cat_raw_tr = df_total_raw.iloc[idx_tr]["attack_cat"].astype(str).values
    label_raw_tr = df_total_raw.iloc[idx_tr]["label"].astype(int).values

    # `Normal` siempre se incluye en el entrenamiento de expertos para que aprendan a no disparar falsas alarmas.
    is_normal_tr = label_raw_tr == 0
    is_vol_tr = np.isin(attack_cat_raw_tr, volumetric_attack_cats) & (~is_normal_tr)
    is_nonvol_tr = (~np.isin(attack_cat_raw_tr, volumetric_attack_cats)) & (~is_normal_tr)

    vol_mask = is_normal_tr | is_vol_tr
    nonvol_mask = is_normal_tr | is_nonvol_tr

    # Si por distribución el subconjunto queda muy chico, entrenamos con todo como fallback
    # (evita que el experto se entrene con poquísimos samples y sea inestable).
    if int(vol_mask.sum()) < 100:
        expert_vol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr, y_tr)
    else:
        expert_vol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr[vol_mask], y_tr[vol_mask])

    if int(nonvol_mask.sum()) < 100:
        expert_nonvol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(X_tr, y_tr)
    else:
        expert_nonvol = DecisionTreeClassifier(random_state=random_state, max_depth=20).fit(
            X_tr[nonvol_mask], y_tr[nonvol_mask]
        )

    moe = MoEModels(
        gate=gate,
        expert_binary=expert_binary,
        expert_vol=expert_vol,
        expert_nonvol=expert_nonvol,
        volumetric_attack_cats=volumetric_attack_cats,
    )

    # Métricas globales del MoE en test
    # Importante: aquí medimos *el sistema completo* (gate+expertos), no cada árbol por separado.
    y_pred = predict_basic_moe(moe, X_te)
    metrics = compute_binary_metrics(y_te, y_pred)
    metrics["gate_accuracy_3class"] = float(accuracy_score(gate_y_te, gate.predict(X_te)))
    metrics["n_test"] = int(y_te.shape[0])

    # También devolvemos índices de test para reportes por attack_cat
    metrics["_idx_test"] = idx_te.tolist()
    return moe, metrics


def predict_basic_moe(moe: MoEModels, X: np.ndarray) -> np.ndarray:
    # Implementación del "enrutamiento" (routing) del MoE.
    # Es "hard routing": el gate elige UN experto (no mezcla ponderada).
    gate_pred = moe.gate.predict(X)  # 0 normal, 1 vol, 2 nonvol
    y_pred = np.zeros(shape=(X.shape[0],), dtype=int)

    idx_normal = np.where(gate_pred == 0)[0]
    idx_vol = np.where(gate_pred == 1)[0]
    idx_nonvol = np.where(gate_pred == 2)[0]

    if idx_normal.size > 0:
        # Para normal usamos el experto generalista (también funciona como fallback).
        y_pred[idx_normal] = moe.expert_binary.predict(X[idx_normal])
    if idx_vol.size > 0:
        y_pred[idx_vol] = moe.expert_vol.predict(X[idx_vol])
    if idx_nonvol.size > 0:
        y_pred[idx_nonvol] = moe.expert_nonvol.predict(X[idx_nonvol])

    return y_pred


# -------------------------
# 4) Métricas y reportes
# -------------------------


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    # Métricas estándar en clasificación binaria.
    # En ciberseguridad suele ser útil reportar F1/Recall/Precision, no solo accuracy.
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def per_attack_cat_detection_table(
    df_total_raw: pd.DataFrame,
    idx_test: List[int],
    y_pred: np.ndarray,
) -> pd.DataFrame:
    """
    Tabla por tipo de ataque (attack_cat) en el split de test:
    - n: cantidad de samples en esa categoría
    - attack_detection_rate: % de predicciones label=1 dentro de esa categoría
    - note: para Normal se interpreta como False Positive Rate (FPR) aproximada
    """

    df_te = df_total_raw.iloc[idx_test].copy()
    df_te["_y_pred"] = y_pred
    df_te["attack_cat"] = df_te["attack_cat"].astype(str)

    rows = []
    for cat, g in df_te.groupby("attack_cat"):
        n = int(g.shape[0])
        rate = float((g["_y_pred"].astype(int) == 1).mean()) if n > 0 else 0.0
        rows.append(
            {
                "attack_cat": cat,
                "n": n,
                "pred_attack_rate": round(rate, 6),
            }
        )
    out = pd.DataFrame(rows).sort_values(["attack_cat"]).reset_index(drop=True)
    return out


def markdown_table(df: pd.DataFrame) -> str:
    """
    Genera tabla Markdown sin depender de `tabulate`.
    Pandas `to_markdown()` lo usa como dependencia opcional y puede no existir en el entorno.
    """

    # Intento 1: usar pandas si está disponible `tabulate`
    try:
        return df.to_markdown(index=False)  # type: ignore[attr-defined]
    except Exception:
        pass

    # Fallback: construcción manual (GitHub-flavored markdown).
    # Esto evita instalar dependencias opcionales en entornos "limpios".
    if df.shape[1] == 0:
        return ""

    df2 = df.copy()
    # convertir NaNs a string vacío
    df2 = df2.replace({np.nan: ""})

    headers = [str(c) for c in df2.columns.tolist()]
    rows = [[str(v) for v in r] for r in df2.to_numpy().tolist()]

    # widths
    widths = [len(h) for h in headers]
    for r in rows:
        for j, cell in enumerate(r):
            widths[j] = max(widths[j], len(cell))

    def fmt_row(cells: List[str]) -> str:
        padded = [cells[j].ljust(widths[j]) for j in range(len(cells))]
        return "| " + " | ".join(padded) + " |"

    out_lines = []
    out_lines.append(fmt_row(headers))
    out_lines.append("| " + " | ".join(["-" * w for w in widths]) + " |")
    for r in rows:
        out_lines.append(fmt_row(r))
    return "\n".join(out_lines)


def write_presentation_markdown(
    out_path: str,
    *,
    dataset_char: Dict[str, Any],
    baseline_metrics: Dict[str, Any],
    moe_metrics: Dict[str, Any],
    baseline_by_cat: pd.DataFrame,
    moe_by_cat: pd.DataFrame,
    volumetric_attack_cats: List[str],
) -> None:
    lines: List[str] = []

    lines.append("## Presentación: Árbol vs MoE (UNSW-NB15)\n")

    lines.append("### 1) Resumen del dataset\n")
    lines.append(f"- **Filas**: {dataset_char.get('n_rows')}\n")
    lines.append(f"- **Columnas**: {dataset_char.get('n_cols')}\n")
    lines.append(f"- **Faltantes (total)**: {dataset_char.get('missing_total')}\n")
    if "label_counts" in dataset_char:
        lines.append(f"- **Distribución `label`**: {dataset_char['label_counts']}\n")
    if "attack_cat_counts" in dataset_char:
        lines.append(f"- **Top `attack_cat`**: {dict(list(dataset_char['attack_cat_counts'].items())[:10])}\n")

    lines.append("### 2) Modelos comparados y configuración\n")
    lines.append("- **Baseline (DecisionTree)**:\n")
    lines.append("  - Tipo: `sklearn.tree.DecisionTreeClassifier`\n")
    lines.append("  - Objetivo: clasificación **binaria** `label` ∈ {0 (Normal), 1 (Ataque)}\n")
    lines.append("  - Features: todas las columnas del CSV menos `['id', 'attack_cat', 'label', 'mitre', 'id_instancia', 'saddr', 'sport', 'daddr', 'dport', 'stime', 'ltime']` (cuando existen)\n")
    lines.append("  - Configuración principal: `random_state=19`, `max_depth=None` (sin límite explícito)\n")
    lines.append(
        "- **MoE básico (árboles)**:\n"
        "  - **Gate**:\n"
        "    - Tipo: `DecisionTreeClassifier`\n"
        "    - Objetivo: problema **3-clases** {0: Normal, 1: Volumétrico, 2: No-volumétrico}\n"
        "    - Configuración: `random_state=19`, `max_depth=20`\n"
        "  - **Expertos (todos `DecisionTreeClassifier`)**:\n"
        "    - `expert_binary`: entrenado con TODO el dataset (Attack vs Normal)\n"
        f"    - `expert_vol`: entrenado con Normal + ataques volumétricos {volumetric_attack_cats}\n"
        "    - `expert_nonvol`: entrenado con Normal + ataques no-volumétricos\n"
        "  - Esquema de inferencia: `gate(x)` selecciona uno de los 3 expertos; ese experto produce la predicción final de ataque (label=1) o normal (label=0).\n"
    )

    lines.append("### 3) Resultados globales (test split)\n")
    global_df = pd.DataFrame(
        [
            {"model": "DecisionTree", **{k: baseline_metrics[k] for k in ["accuracy", "precision", "recall", "f1"]}},
            {"model": "MoE_basic", **{k: moe_metrics[k] for k in ["accuracy", "precision", "recall", "f1"]}},
        ]
    )
    lines.append(markdown_table(global_df) + "\n")

    lines.append("### 4) Resultado por tipo de ataque (rate de 'predice ataque')\n")
    lines.append(
        "En la siguiente tabla, para cada `attack_cat` se muestra el **porcentaje de flujos donde el modelo predijo ataque (label=1)** en el conjunto de test.\n"
        "- En la fila `Normal`, este valor se interpreta como una **tasa de falsos positivos aproximada**.\n"
    )

    # Unir tablas baseline/moe por attack_cat en una sola tabla
    base_df = baseline_by_cat.rename(columns={"pred_attack_rate": "baseline_attack_rate"})
    moe_df = moe_by_cat.rename(columns={"pred_attack_rate": "moe_attack_rate"})
    merged = (
        base_df[["attack_cat", "baseline_attack_rate"]]
        .merge(moe_df[["attack_cat", "moe_attack_rate"]], on="attack_cat", how="outer")
        .fillna(0.0)
        .sort_values("attack_cat")
        .reset_index(drop=True)
    )

    lines.append(markdown_table(merged) + "\n")

    lines.append("### 5) Nota de interpretación\n")
    lines.append(
        "- Valores cercanos a 1.0 en categorías de ataque indican **alta tasa de detección** (el modelo casi siempre marca ataque).\n"
        "- Valores cercanos a 0.0 en `Normal` indican **baja tasa de falsas alarmas**.\n"
    )

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")


# -------------------------
# 5) Main
# -------------------------


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default="UNSW_NB15_testing-set.csv")
    p.add_argument("--out-dir", default="unsw_outputs")
    p.add_argument("--test-size", type=float, default=0.30)
    p.add_argument("--random-state", type=int, default=19)
    p.add_argument(
        "--volumetric-cats",
        default="DoS",
        help="Lista separada por comas. Por defecto: DoS",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Cargar dataset raw (sin encoders)
    df_total = pd.read_csv(args.csv)

    # 2) Caracterización (para reporte/presentación)
    char = characterize_dataset(df_total)
    save_characterization(str(out_dir / "dataset_characterization.json"), char)

    # 3) Preprocesado notebook-style (LabelEncoder + armado de X/y)
    enc = fit_encoders(df_total)
    df_attack = apply_encoders_notebook_style(df_total, enc)
    X_all, y_all, feature_names = make_xy_binary(df_attack)

    # 4) Split + baseline (árbol binario)
    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X_all,
        y_all,
        np.arange(X_all.shape[0]),
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y_all,
    )

    # Entrenamiento baseline
    baseline = train_decision_tree_binary(X_tr, y_tr, random_state=args.random_state)
    baseline_pred = baseline.predict(X_te)
    baseline_metrics = compute_binary_metrics(y_te, baseline_pred)
    baseline_metrics["n_test"] = int(y_te.shape[0])
    baseline_metrics["_idx_test"] = idx_te.tolist()

    # 5) MoE básico (gate + 3 expertos)
    volumetric_attack_cats = [x.strip() for x in str(args.volumetric_cats).split(",") if x.strip()]
    moe, moe_metrics = train_basic_moe(
        df_total_raw=df_total,
        df_attack_encoded=df_attack,
        X_all=X_all,
        y_all=y_all,
        feature_names=feature_names,
        volumetric_attack_cats=volumetric_attack_cats,
        test_size=args.test_size,
        random_state=args.random_state,
    )

    # 6) Reportes por tipo de ataque (attack_cat) para comparar comportamientos
    baseline_by_cat = per_attack_cat_detection_table(df_total, baseline_metrics["_idx_test"], baseline_pred)

    # Para MoE: recomputamos predicciones sobre el MISMO idx_te usado por el entrenamiento MoE (para consistencia del reporte MoE)
    moe_idx_te = moe_metrics["_idx_test"]
    moe_pred = predict_basic_moe(moe, X_all[np.array(moe_idx_te)])
    moe_by_cat = per_attack_cat_detection_table(df_total, moe_idx_te, moe_pred)

    # 7) Guardar artefactos mínimos para reusar luego (por ejemplo, integrar un MoE más avanzado).
    joblib.dump(baseline, str(out_dir / "baseline_decision_tree.pkl"))
    joblib.dump(moe, str(out_dir / "moe_basic.pkl"))
    joblib.dump(enc, str(out_dir / "encoders.pkl"))
    (out_dir / "feature_names.json").write_text(json.dumps(feature_names, indent=2), encoding="utf-8")

    # Guardar tablas en CSV para abrir en Excel / adjuntar a reportes.
    baseline_by_cat.to_csv(out_dir / "baseline_by_attack_cat.csv", index=False)
    moe_by_cat.to_csv(out_dir / "moe_by_attack_cat.csv", index=False)

    # 8) Presentación markdown lista para convertir en slides.
    write_presentation_markdown(
        str(out_dir / "presentacion_resultados.md"),
        dataset_char=char,
        baseline_metrics=baseline_metrics,
        moe_metrics=moe_metrics,
        baseline_by_cat=baseline_by_cat,
        moe_by_cat=moe_by_cat,
        volumetric_attack_cats=volumetric_attack_cats,
    )

    print("OK. Archivos generados en:", str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

