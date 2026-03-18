"""
Versión en .py del notebook `SHAP_UNSW_NB15.ipynb`.

La idea es **copiar y pegar** (lo más fiel posible) el código del notebook,
pero organizado en **funciones por paso**, para poder:
    - llamar fácilmente al Árbol de Decisión clásico
    - reutilizar el preprocesado y los datos para otros modelos (por ejemplo, un MoE)

IMPORTANTE:
- Se han respetado los nombres de variables y la estructura general del notebook.
- Los comentarios originales se mantienen siempre que ha sido posible.
"""

import warnings

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier


warnings.filterwarnings("ignore")


# ============================================================
# Sección 0: Lectura de datos
# ============================================================


def lectura_datos(
    url_train=None,
    url_test="UNSW_NB15_testing-set.csv",
):
    """
    **Lectura datos**

    Leer los conjuntos de datos y combinar los conjuntos de entrenamiento y prueba en un DataFrame.
    En el notebook finalmente se trabaja sólo con el testing-set para construir el ejemplo.
    """

    # trabajar con un subconjunto mientras construimos código
    # url_train = 'UNSW_NB15_training-set.csv'
    # df = pd.read_csv(url_train)
    # df_test = pd.read_csv(url_test)
    #
    # df_total = pd.concat([df, df_test])

    df_total = pd.read_csv(url_test)
    return df_total


# ============================================================
# Sección 1: Codificación de variables categóricas
# ============================================================


def codificar_categoricas(df_total: pd.DataFrame) -> pd.DataFrame:
    """
    Replica la celda:
        from sklearn.preprocessing import LabelEncoder
        import joblib

        df_attack = df_total.copy()
        ...
        df_attack['proto'] = LE_proto.fit_transform(df_attack['proto'])
        joblib.dump(LE_proto, 'LE_proto.pkl')
        ...
    """

    # Se hace una copia del dataset original para no alterar los datos iniciales
    df_attack = df_total.copy()

    # Se inicializan múltiples herramientas llamadas 'LabelEncoder'.
    # Su función es tomar las categorías en formato texto y asignarles un número.
    LE_proto = LabelEncoder()
    LE_service = LabelEncoder()
    LE_state = LabelEncoder()
    LE_attack_cat = LabelEncoder()
    LE_label = LabelEncoder()

    df_attack["proto"] = LE_proto.fit_transform(df_attack["proto"])
    joblib.dump(
        LE_proto,
        "LE_proto.pkl",
    )  # joblib.dump guarda este "aprendizaje" en un archivo local (.pkl)

    df_attack["service"] = LE_service.fit_transform(df_attack["service"])
    joblib.dump(LE_service, "LE_service.pkl")

    df_attack["state"] = LE_state.fit_transform(df_attack["state"])
    joblib.dump(LE_state, "LE_state.pkl")

    df_attack["attack_cat"] = LE_attack_cat.fit_transform(df_attack["attack_cat"])
    joblib.dump(LE_attack_cat, "LE_attack_cat.pkl")

    df_attack["label"] = LE_label.fit_transform(df_attack["label"])
    # joblib.dump(LE_label, 'LE_label.pkl')

    return df_attack


# ============================================================
# Sección 2: Separación de X / y
# ============================================================


def separar_variables(df_attack: pd.DataFrame):
    """
    ### 2. Separación de Variables Predictoras (X) y Etiquetas (y)
    """

    # Identificamos cuál es la variable a predecir (la etiqueta 'y')
    # En este caso, asignamos la columna 'label' entera a nuestra 'y_total' (valores 0 ó 1)
    y_total = df_attack["label"]

    # Retiramos del grupo de datos original las columnas que no nos sirven para predecir si es un ataque.
    # - 'id' es solo un identificador autoincremental sin valor predecible
    # - 'attack_cat' es la categoría, la borramos para que el modelo no se entrene haciendo trampa
    #   y porque ahora solo queremos una predicción binaria.
    # - 'label' ya se guardó en y_total.
    df_attack_proc = df_attack.drop(["id", "attack_cat", "label"], axis=1)

    # Se toma la tabla de datos procesados (un DataFrame de Pandas) y se saca
    # solamente su matriz de valores crudos (un arreglo NumPy).
    X_real = df_attack_proc.values

    # NOTA: En el código original se tienen líneas comentadas que usan StandardScaler().
    # Es una práctica opcional (pero recomendada) para estandarizar los datos.
    # En este caso NO es estrictamente necesario: el modelo usado es un Árbol de Decisión.
    #
    # scaler = StandardScaler()
    # scaler.fit(X_real)
    # X_total = scaler.transform(X_real)

    X_total = X_real
    n_classes = 2

    return X_total, y_total, df_attack_proc.columns.tolist(), n_classes


# ============================================================
# Sección 3: Entrenamiento del Árbol de Decisión
# ============================================================


def entrenar_arbol_decision(X_total, y_total):
    """
    ### 3. Entrenamiento del Modelo de Árbol de Decisión
    """

    # crear clasificador
    # Se reserva memoria para nuestro modelo de aprendizaje, que es un clasificador
    # estructurado como árbol de decisiones.
    clf = DecisionTreeClassifier(random_state=19)

    # Revolvemos y partimos los datos totales (X e y) en una relación de 70% para
    # entrenamiento (tr) y 30% reservado para evaluar el modelo después (t / test_size=0.30)
    X_tr, X_t, y_tr, y_t = train_test_split(
        X_total,
        y_total,
        test_size=0.30,
        random_state=19,
    )

    print("- Attack vs Normal -")

    # Se crea una tabla para almacenar el resumen de rendimiento en un futuro,
    performance_attack = pd.DataFrame(
        columns=["Classifier", "accuracy", "recall", "precision", "f1"],
    )

    # entrenamos con datos entrenamiento
    # La orden fundamental 'fit': obliga al árbol de decisión a deducir patrones usando
    # las entradas (X_tr) contra sus resultados reales correspondientes (y_tr)
    clf = clf.fit(X_tr, y_tr)

    return clf, X_tr, X_t, y_tr, y_t, performance_attack


# ============================================================
# Sección 4: Evaluación del modelo
# ============================================================


def evaluar_modelo(clf, X_t, y_t, performance_attack: pd.DataFrame) -> pd.DataFrame:
    """
    ### 4. Evaluación y Comportamiento con los Datos
    """

    # como nos va con los datos de testing
    # Ordenamos al modelo generar intentos de adivinanza (predicciones) sobre el 30%
    # de datos no vistos
    y_predict = clf.predict(X_t)

    # A partir de este momento, generamos las evaluaciones comparando las predicciones (y_predict)
    # versus el resultado genuino que siempre debió haber tenido (y_t)
    accuracy = accuracy_score(y_t, y_predict)  # El porcentaje general de aciertos
    recall = recall_score(y_t, y_predict)  # Sensibilidad: cuántos ataques reales capturó el modelo
    precision = precision_score(y_t, y_predict)  # Efectividad: si el modelo dice que es ataque, qué tan probable es
    f1 = f1_score(y_t, y_predict)  # Balancea la precisión y fiabilidad general (recall)

    performance_attack.loc[0] = ["Decision Tree", accuracy, recall, precision, f1]

    print(performance_attack)
    print("")
    print("Classification Report:")
    print(classification_report(y_t, y_predict))

    matriz_confusion = confusion_matrix(y_t, y_predict)
    print("Matriz de Confusión:")
    print(matriz_confusion)

    return performance_attack


# ============================================================
# EXTRA: Ajuste de hiperparámetros con GridSearchCV
# ============================================================


def ajustar_hiperparametros(X_tr, y_tr) -> DecisionTreeClassifier:
    """
    EXTRA: Ajuste de hiperparámetros con GridSearchCV, tal como en el notebook.
    """

    # Definimos el espacio de búsqueda
    param_grid = {
        "criterion": ["gini", "entropy"],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 5, 10],
        "class_weight": [None, "balanced"],  # Útil si hay pocos ataques comparado con tráfico normal
    }

    grid_search = GridSearchCV(
        DecisionTreeClassifier(random_state=19),
        param_grid,
        cv=5,
        scoring="f1",
    )
    grid_search.fit(X_tr, y_tr)

    print("Mejores parámetros encontrados:", grid_search.best_params_)
    best_model = grid_search.best_estimator_
    return best_model


# ============================================================
# Sección SHAP: explicación del modelo
# ============================================================


def preparar_y_calcular_shap(df_attack: pd.DataFrame, X_t, clf):
    """
    Sección 1 y 2 de SHAP del notebook:
    - shap.initjs()
    - column_names = df_attack.columns
    - X_t_dataframe = pd.DataFrame(X_t, columns=column_names)
    - explainer = shap.Explainer(clf)
    - shap_values_clf = explainer.shap_values(X_t_dataframe)
    """

    try:
        import shap
    except ImportError:
        print(
            "SHAP no está instalado. Ejecuta 'pip install shap' si quieres calcular explicaciones SHAP."
        )
        return None, None

    # Inicializamos el soporte de javascript para que los gráficos interactivos de SHAP se dibujen correctamente
    shap.initjs()

    # Guardamos los nombres originales de las características del dataset
    column_names = df_attack.columns

    # Convertimos la matriz de test (X_t) a un DataFrame para que SHAP reconozca las etiquetas
    X_t_dataframe = pd.DataFrame(X_t, columns=column_names)

    # Instanciamos el "Explicador" de SHAP.
    # Le pasamos el modelo (el Árbol de Decisión 'clf') que queremos auditar
    explainer = shap.Explainer(clf)

    # ATENCIÓN: Esta línea calcula la fuerza de cada variable.
    # Puede tardar unos segundos/minutos porque evalúa registro por registro.
    shap_values_clf = explainer.shap_values(X_t_dataframe)

    return shap_values_clf, X_t_dataframe


def visualizar_shap_summary(shap_values_clf, X_t_dataframe):
    """
    ### **Sección 3**: Visualización del Resumen (Summary Plot)
    """

    if shap_values_clf is None or X_t_dataframe is None:
        print("No se pudieron generar gráficos SHAP (no hay valores calculados).")
        return

    import shap

    # Este comando imprimirá un gráfico muy famoso de SHAP.
    shap.summary_plot(shap_values_clf, X_t_dataframe)


# ============================================================
# Sección final: guardar modelo y predecir nueva instancia
# ============================================================


def guardar_modelo_y_encoders(clf, df_attack: pd.DataFrame):
    """
    Guarda el modelo entrenado y los LabelEncoders tal y como en el notebook:
        joblib.dump(clf, 'modelo_entrenado.pkl')
        joblib.dump(LE_proto, 'LE_proto.pkl')
        ...

    Aquí, para simplificar y centralizar, asumimos que ya se han generado y
    guardado los encoders durante `codificar_categoricas`.
    """

    joblib.dump(clf, "modelo_entrenado.pkl")
    print("Modelo guardado en 'modelo_entrenado.pkl'.")


def cargar_modelo_y_predecir_interactivo():
    """
    Replica la idea de la parte final del notebook:
    - Cargar modelo y LabelEncoders desde archivos .pkl
    - Pedir por consola una instancia (fila tipo CSV)
    - Transformar proto/service/state con los LabelEncoders
    - Convertir el resto de campos a float
    - Realizar la predicción con `clasificador.predict([muestra])`
    """

    clasificador = joblib.load("modelo_entrenado.pkl")
    LE_proto = joblib.load("LE_proto.pkl")
    LE_service = joblib.load("LE_service.pkl")
    LE_state = joblib.load("LE_state.pkl")

    instancia = input("Ingresa los valores de la instancia (separados por comas): ")
    valores = instancia.split(",")

    # En el notebook se eliminan id, attack_cat y label (primer y dos últimos campos)
    valores = [valores[i] for i in range(len(valores)) if i not in [0, len(valores) - 2, len(valores) - 1]]

    # proto, service y state se transforman con sus respectivos LabelEncoders
    # (índices 1, 2 y 3 después de filtrar)
    valores[1] = LE_proto.transform([valores[1]])[0]
    # service puede tener clases fuera del entrenamiento: se manejaba con un condicional en el notebook
    if valores[2] in LE_service.classes_:
        valores[2] = LE_service.transform([valores[2]])[0]
    else:
        valores[2] = -1
    valores[3] = LE_state.transform([valores[3]])[0]

    muestra = [float(x) if i not in (1, 2, 3) else x for i, x in enumerate(valores)]
    prediction = clasificador.predict([muestra])

    print(f"Predicción para la instancia: {prediction[0]}")


# ============================================================
# Ejecución tipo "notebook" en un solo main
# ============================================================


def main():
    """
    Ejecuta de inicio a fin el flujo principal del notebook:
    1. Lectura de datos
    2. Codificación de categóricas
    3. Separación X / y
    4. Entrenamiento Árbol de Decisión
    5. Evaluación
    6. (Opcional) Ajuste de hiperparámetros con GridSearch
    7. (Opcional) Cálculo SHAP + summary plot
    8. (Opcional) Guardar modelo y predecir instancia

    Esta función es sólo una guía; puedes comentar/activar bloques según lo que quieras probar.
    """

    # 1. Lectura
    df_total = lectura_datos()

    # 2. Codificación
    df_attack = codificar_categoricas(df_total)

    # 3. Separación X / y
    X_total, y_total, feature_names, _ = separar_variables(df_attack)

    # 4. Entrenamiento Árbol de Decisión
    clf, X_tr, X_t, y_tr, y_t, performance_attack = entrenar_arbol_decision(X_total, y_total)

    # 5. Evaluación
    evaluar_modelo(clf, X_t, y_t, performance_attack)

    # 6. (Opcional) Ajuste de hiperparámetros
    # best_clf = ajustar_hiperparametros(X_tr, y_tr)
    # evaluar_modelo(best_clf, X_t, y_t, performance_attack)

    # 7. (Opcional) SHAP
    # shap_values_clf, X_t_dataframe = preparar_y_calcular_shap(df_attack, X_t, clf)
    # visualizar_shap_summary(shap_values_clf, X_t_dataframe)

    # 8. (Opcional) Guardar modelo y predicción interactiva
    # guardar_modelo_y_encoders(clf, df_attack)
    # cargar_modelo_y_predecir_interactivo()


if __name__ == "__main__":
    main()

