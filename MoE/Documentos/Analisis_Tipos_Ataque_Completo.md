# Análisis Completo de Tipos de Ataque: Detección mediante Argus y Características Contextuales

Este documento presenta un análisis exhaustivo de los **9 tipos de ataques** detectados por Intrusion.Aware, explicando cómo el sistema utiliza **Argus** para capturar flujos de red y cómo las **características contextuales** (ventanas temporales) permiten identificar patrones de ataque que no son visibles en un solo flujo.

> **Documentos Relacionados:**
> - **[Flujo de Captura y Clasificación](Flujo_Captura_Clasificacion.md)**: Proceso técnico completo de captura, procesamiento y clasificación con referencias a código.
> - **[Documentación Completa del Sistema](Documentacion_Completa_Sistema.md)**: Arquitectura completa, componentes y fundamentos técnicos de Argus.

---

## Tabla de Contenidos

1. [Introducción y Metodología](#1-introducción-y-metodología)
2. [Fundamentos Técnicos: Argus y Características Contextuales](#2-fundamentos-técnicos-argus-y-características-contextuales)
3. [Pipeline General de Detección](#3-pipeline-general-de-detección)
4. [Análisis por Tipo de Ataque](#4-análisis-por-tipo-de-ataque)
   - [4.1 Fuzzers](#41-fuzzers)
   - [4.2 Analysis](#42-analysis)
   - [4.3 DoS (Denial of Service)](#43-dos-denial-of-service)
   - [4.4 Exploits](#44-exploits)
   - [4.5 Generic (Fuerza Bruta)](#45-generic-fuerza-bruta)
   - [4.6 Reconnaissance](#46-reconnaissance)
   - [4.7 Shellcode](#47-shellcode)
   - [4.8 Worms](#48-worms)
   - [4.9 Backdoor](#49-backdoor)
5. [Resumen Comparativo: Ventanas Temporales](#5-resumen-comparativo-ventanas-temporales)
6. [Conclusiones y Recomendaciones](#6-conclusiones-y-recomendaciones)
7. [Anexos](#7-anexos)
   - [A. Generación de Dataset Etiquetado](#a-generación-de-dataset-etiquetado)
   - [B. Ejecución en Producción: Consulta al Modelo](#b-ejecución-en-producción-consulta-al-modelo)

---

## 1. Introducción y Metodología

### 1.1 Objetivo del Documento

Este documento analiza **cómo Intrusion.Aware detecta cada tipo de ataque** mediante:
- **Características básicas** extraídas por Argus (30 campos por flujo)
- **Características contextuales** (`ct_*`) calculadas sobre ventanas temporales
- **Patrones de comportamiento** que requieren múltiples flujos para ser identificados

### 1.2 Metodología de Análisis

Este análisis contrasta **tres visiones** sobre cada tipo de ataque:

1. **Bibliografía (Moustafa et al., 2015)**
   - Definiciones oficiales del dataset UNSW-NB15
   - Características técnicas utilizadas
   - Metodología de generación de features contextuales

2. **Feedback de Analistas SOC**
   - Validación CSIRT (27 octubre 2025): 11 analistas, 33 casos
   - Validación REUNA (28 octubre 2025): 2 analistas, 6 casos
   - Features identificadas como relevantes en la práctica

3. **Hipótesis Teóricas del Proyecto**
   - Variables clave identificadas por el equipo de investigación
   - Basadas en análisis del dataset UNSW-NB15 y literatura

### 1.3 Concepto Clave: Ventanas Temporales

**Problema fundamental:** Muchos ataques no pueden detectarse observando un solo flujo de red. Requieren análisis de **múltiples flujos** en una **ventana temporal**.

**Ejemplo ilustrativo:**
- **Un solo flujo** con alta tasa de paquetes → Podría ser una descarga legítima grande
- **20 flujos simultáneos** hacia el mismo destino con alta tasa → **DoS**

**Solución:** Características contextuales (`ct_*`) que cuentan ocurrencias previas en un buffer de 100 conexiones.

**Referencia Moustafa et al. (2015):**
> "The features 36-47 of Table VI are intended to sort accordingly with the last time feature to capture similar characteristics of the connection records for each 100 connections sequentially ordered."

---

## 2. Fundamentos Técnicos: Argus y Características Contextuales

> **Para la explicación técnica completa de Argus:** Consulta la sección "Fundamentos Técnicos: Argus y el Procesamiento de Flujos de Red" en [Documentación Completa del Sistema](Documentacion_Completa_Sistema.md).

Esta sección resume los conceptos fundamentales necesarios para entender cómo se detectan los ataques. Para detalles técnicos completos, consulta la documentación referenciada.

### 2.1 Conceptos Fundamentales: Flujos, Paquetes y Ataques

#### ¿Qué es un Flujo de Red?

Un **flujo de red** es una secuencia de paquetes que comparten las mismas características de identificación. Argus utiliza la definición clásica de **5-tuple** para agrupar paquetes en flujos:

```
Flujo = (saddr, sport, daddr, dport, proto)
```

**Ejemplo:**
- **Flujo 1**: `(192.168.1.100, 54321, 10.0.0.1, 80, TCP)` → Conexión HTTP desde 192.168.1.100:54321 hacia 10.0.0.1:80
- **Flujo 2**: `(192.168.1.100, 54322, 10.0.0.1, 80, TCP)` → **DIFERENTE** flujo (puerto origen diferente)
- **Flujo 3**: `(192.168.1.100, 54321, 10.0.0.1, 443, TCP)` → **DIFERENTE** flujo (puerto destino diferente)

**Regla importante:** Si cambia **cualquier** componente del 5-tuple, es un **nuevo flujo**.

#### ¿Cómo Argus Construye los Flujos?

Argus construye flujos mediante un proceso de **agrupación de paquetes** basado en el **5-tuple**. El proceso funciona así:

**Proceso de Construcción de Flujo:**

1. **Argus captura paquetes** individuales de la interfaz de red (usando libpcap).

2. **Para cada paquete, extrae el 5-tuple:**
   - `saddr`: Dirección IP origen
   - `sport`: Puerto origen
   - `daddr`: Dirección IP destino
   - `dport`: Puerto destino
   - `proto`: Protocolo (TCP, UDP, ICMP, etc.)

3. **Argus mantiene una tabla de flujos activos** en memoria:
   - Cada entrada en la tabla representa un flujo único (identificado por 5-tuple).
   - Si un paquete tiene un 5-tuple que **ya existe** en la tabla → Se agrega a ese flujo existente.
   - Si un paquete tiene un 5-tuple **nuevo** → Se crea un nuevo flujo en la tabla.

4. **Argus acumula estadísticas** para cada flujo:
   - Cuenta paquetes en cada dirección (`spkts`, `dpkts`).
   - Suma bytes en cada dirección (`sbytes`, `dbytes`).
   - Calcula tiempos (`stime`, `ltime`, `dur`).
   - Calcula tasas y métricas derivadas (`rate`, `sload`, `dload`, etc.).

5. **Argus genera un registro de flujo** cuando:
   - El flujo se cierra (ej: TCP FIN, timeout).
   - Se alcanza un intervalo de reporte (por defecto, cada 60 segundos para flujos activos).
   - Se alcanza un límite de tiempo o tamaño.

**Ejemplo Detallado del Proceso:**

```
┌─────────────────────────────────────────────────────────────┐
│                    PAQUETES EN LA RED                       │
│  Paquete 1: 192.168.1.100:54321 → 10.0.0.1:80 (TCP SYN)    │
│  Paquete 2: 192.168.1.100:54321 → 10.0.0.1:80 (TCP ACK)    │
│  Paquete 3: 10.0.0.1:80 → 192.168.1.100:54321 (TCP SYN-ACK)│
│  Paquete 4: 192.168.1.100:54321 → 10.0.0.1:80 (TCP DATA)  │
│  Paquete 5: 10.0.0.1:80 → 192.168.1.100:54321 (TCP DATA)  │
│  ... (más paquetes)                                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    ARGUS: PROCESO INTERNO                   │
│                                                              │
│  Tabla de Flujos Activos (en memoria):                      │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Flujo ID: 1                                         │    │
│  │ 5-tuple: (192.168.1.100, 54321, 10.0.0.1, 80, TCP)│    │
│  │ Estado: ACTIVO                                      │    │
│  │ Estadísticas acumuladas:                            │    │
│  │   • spkts: 2 (paquetes 1, 2, 4)                    │    │
│  │   • dpkts: 2 (paquetes 3, 5)                      │    │
│  │   • sbytes: 1024 + 512 + 2048 = 3584               │    │
│  │   • dbytes: 512 + 1024 = 1536                     │    │
│  │   • stime: Tiempo del paquete 1                    │    │
│  │   • ltime: Tiempo del paquete 5 (último)           │    │
│  │   • dur: ltime - stime                            │    │
│  │   • rate: (spkts + dpkts) / dur                    │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  Para cada nuevo paquete:                                   │
│  1. Extrae 5-tuple                                          │
│  2. Busca en tabla de flujos activos                        │
│  3. Si existe → Actualiza estadísticas del flujo            │
│  4. Si no existe → Crea nuevo flujo en la tabla              │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    REGISTRO DE FLUJO GENERADO               │
│  (Cuando el flujo se cierra o se alcanza intervalo)        │
│                                                              │
│  Flujo: (192.168.1.100, 54321, 10.0.0.1, 80, TCP)          │
│  • stime: Tiempo del primer paquete                         │
│  • ltime: Tiempo del último paquete                         │
│  • dur: Duración total                                       │
│  • spkts: Total de paquetes origen → destino               │
│  • dpkts: Total de paquetes destino → origen               │
│  • sbytes: Total de bytes origen → destino                  │
│  • dbytes: Total de bytes destino → origen                  │
│  • rate: Paquetes por segundo                               │
│  • state: Estado del flujo (EST, FIN, etc.)                │
│  • ... (30 características totales)                         │
└─────────────────────────────────────────────────────────────┘
```

**Puntos Importantes sobre la Construcción de Flujos:**

1. **Un flujo puede contener múltiples paquetes** (típicamente decenas o cientos).
2. **Un flujo se identifica únicamente por el 5-tuple** - si cambia cualquier componente, es un nuevo flujo.
3. **Argus mantiene flujos activos en memoria** hasta que se cierran o expiran.
4. **Las características del flujo se calculan agregando** las métricas de todos los paquetes que pertenecen a ese flujo.

**Punto crítico:** Un ataque puede generar **múltiples flujos** (no múltiples paquetes). Por ejemplo:
- **Ataque DoS**: 20 **flujos** simultáneos desde diferentes puertos origen hacia el mismo destino
  - Cada flujo contiene múltiples paquetes (SYN, ACK, DATA, etc.)
  - Resultado: 20 flujos diferentes, cada uno con sus propios paquetes
- **Ataque Fuzzer**: 100 **flujos** secuenciales desde la misma IP hacia el mismo servicio
  - Cada intento de fuzzing genera un nuevo flujo (nuevo puerto origen)
  - Resultado: 100 flujos diferentes
- **Ataque Reconnaissance**: 50 **flujos** desde la misma IP hacia diferentes puertos/destinos
  - Cada escaneo de puerto genera un nuevo flujo
  - Resultado: 50 flujos diferentes

### 2.2 Características Contextuales (ct_*): Cálculo y Significado

Las características contextuales `ct_*` se calculan **contando cuántos flujos previos** (en el buffer de contexto) cumplen ciertas condiciones. Esto permite detectar patrones que requieren múltiples flujos.

> **Para detalles técnicos completos del cálculo:** Consulta la sección "Enriquecimiento Contextual (Ventanas Temporales)" en [Documentacion_Completa_Sistema.md](Documentacion_Completa_Sistema.md#enriquecimiento-contextual-ventanas-temporales).

#### Cómo se Calculan las ct_*

El sistema mantiene un **buffer FIFO** (First In, First Out) con las últimas **100 conexiones** procesadas. Para cada nuevo flujo, se calculan las características contextuales contando flujos en este buffer:

```csharp
// Pseudocódigo del cálculo (basado en FeatureEnricher.cs)

// Buffer de contexto: Queue con las últimas 100 conexiones
Queue<Dictionary<string, string>> contextBuffer = new();

// Para cada nuevo flujo que llega:
Dictionary<string, string> nuevoFlujo = { ... };

// ct_dst_ltm: Cuántos flujos previos van hacia el mismo destino
ct_dst_ltm = contextBuffer.Count(flujo => flujo["daddr"] == nuevoFlujo["daddr"]);

// ct_src_ltm: Cuántos flujos previos vienen de la misma IP origen
ct_src_ltm = contextBuffer.Count(flujo => flujo["saddr"] == nuevoFlujo["saddr"]);

// ct_srv_src: Cuántos flujos previos del mismo servicio desde misma IP origen
ct_srv_src = contextBuffer.Count(flujo => 
    flujo["service"] == nuevoFlujo["service"] && 
    flujo["saddr"] == nuevoFlujo["saddr"]);

// ct_srv_dst: Cuántos flujos previos del mismo servicio hacia misma IP destino
ct_srv_dst = contextBuffer.Count(flujo => 
    flujo["service"] == nuevoFlujo["service"] && 
    flujo["daddr"] == nuevoFlujo["daddr"]);

// ct_src_dport_ltm: Cuántos flujos previos desde misma IP origen hacia mismo puerto
ct_src_dport_ltm = contextBuffer.Count(flujo => 
    flujo["saddr"] == nuevoFlujo["saddr"] && 
    flujo["dport"] == nuevoFlujo["dport"]);

// ct_state_ttl: Cuántos flujos previos con mismo estado y TTL
ct_state_ttl = contextBuffer.Count(flujo => 
    flujo["state"] == nuevoFlujo["state"] && 
    flujo["sttl"] == nuevoFlujo["sttl"]);

// ct_dst_src_ltm: Cuántos flujos previos entre mismas IPs origen y destino
ct_dst_src_ltm = contextBuffer.Count(flujo => 
    flujo["daddr"] == nuevoFlujo["daddr"] && 
    flujo["saddr"] == nuevoFlujo["saddr"]);

// Agregar el nuevo flujo al buffer
contextBuffer.Enqueue(nuevoFlujo);
if (contextBuffer.Count > 100) {
    contextBuffer.Dequeue(); // Eliminar el más antiguo
}
```

#### Tabla de Características Contextuales

| Característica | Cálculo | Detecta | Ejemplo |
|----------------|---------|---------|---------|
| **`ct_dst_ltm`** | Flujos previos hacia misma IP destino (`daddr`) | DoS, Analysis | Si `ct_dst_ltm = 20` → 20 flujos previos atacando el mismo destino |
| **`ct_src_ltm`** | Flujos previos desde misma IP origen (`saddr`) | Reconnaissance, Worms | Si `ct_src_ltm = 50` → 50 flujos previos desde el mismo origen |
| **`ct_srv_src`** | Flujos previos del mismo servicio desde misma IP origen | Fuzzers, Generic | Si `ct_srv_src = 100` → 100 intentos HTTP desde la misma IP |
| **`ct_srv_dst`** | Flujos previos del mismo servicio hacia misma IP destino | DoS | Si `ct_srv_dst = 20` → 20 conexiones HTTP hacia el mismo servidor |
| **`ct_src_dport_ltm`** | Flujos previos desde misma IP origen hacia mismo puerto destino | Generic, Fuzzers | Si `ct_src_dport_ltm = 100` → 100 intentos SSH desde la misma IP |
| **`ct_state_ttl`** | Flujos previos con mismo estado y TTL | Analysis, Backdoor | Si `ct_state_ttl = 10` → 10 conexiones con mismo estado y TTL |
| **`ct_dst_src_ltm`** | Flujos previos entre mismas IPs origen y destino | Backdoor | Si `ct_dst_src_ltm = 5` → 5 conexiones previas entre estas IPs |

#### Resumen Ejecutivo: Cómo Funcionan las ct_* en la Práctica

**¿Qué son estas variables?**
- Son **contadores** que indican cuántos flujos previos (de las últimas 100 conexiones procesadas) cumplen cierta condición.
- Se calculan **para cada flujo nuevo** antes de agregarlo al buffer de contexto.
- **Aumentan de valor** cuando hay múltiples flujos con características similares.

**¿Cómo aumentan estos contadores?**

Ejemplo práctico con `ct_dst_ltm` (contador de flujos hacia mismo destino):

```
Tiempo    Flujo Procesado                    ct_dst_ltm    Explicación
─────────────────────────────────────────────────────────────────────────
T=0s      Flujo 1: 192.168.1.100 → 10.0.0.1   = 0          Buffer vacío
T=1s      Flujo 2: 192.168.1.101 → 10.0.0.1   = 1          1 flujo previo hacia 10.0.0.1
T=2s      Flujo 3: 192.168.1.102 → 10.0.0.1   = 2          2 flujos previos hacia 10.0.0.1
T=3s      Flujo 4: 192.168.1.103 → 10.0.0.1   = 3          3 flujos previos hacia 10.0.0.1
...
T=19s     Flujo 20: 192.168.1.119 → 10.0.0.1  = 19         19 flujos previos hacia 10.0.0.1
T=20s     Flujo 21: 192.168.1.120 → 10.0.0.2   = 0          Diferente destino, cuenta flujos hacia 10.0.0.2
```

**Regla clave:** El contador cuenta **solo flujos previos en el buffer** (últimas 100 conexiones), no todos los flujos del ataque.

**¿Un ataque genera múltiples paquetes? ¿Cómo los agarra Argus?**

Sí, un ataque genera **múltiples paquetes**, pero Argus los agrupa en **flujos**:

```
Ataque DoS lanzado:
├─ Paquete 1: 192.168.1.100:50001 → 10.0.0.1:80 (SYN)
├─ Paquete 2: 192.168.1.100:50001 → 10.0.0.1:80 (ACK)
├─ Paquete 3: 10.0.0.1:80 → 192.168.1.100:50001 (SYN-ACK)
├─ Paquete 4: 192.168.1.100:50001 → 10.0.0.1:80 (DATA)
│  └─ Argus agrupa estos 4 paquetes → FLUJO 1
│
├─ Paquete 5: 192.168.1.100:50002 → 10.0.0.1:80 (SYN)
├─ Paquete 6: 192.168.1.100:50002 → 10.0.0.1:80 (ACK)
│  └─ Argus agrupa estos 2 paquetes → FLUJO 2 (diferente puerto origen)
│
└─ ... (más flujos)

Resultado: 20 flujos diferentes (cada uno con múltiples paquetes)
```

**¿30 segundos es suficiente para agarrar todos los paquetes de un ataque?**

**Respuesta corta:** Depende del ataque, pero **sí es suficiente** para la mayoría.

**Explicación:**
- **30 segundos** es el intervalo del **Timed Buffer** (acumula flujos antes de procesarlos).
- **NO es una limitación** para capturar ataques largos.
- Argus captura **todos los paquetes** en tiempo real, sin límite de tiempo.
- El sistema procesa flujos cada 30 segundos, pero **sigue capturando** mientras el ataque continúa.

**¿Qué pasa si el ataque dura más de 30 segundos (ej: 3 minutos)?**

El sistema **sigue funcionando normalmente**:

```
Ataque DoS de 3 minutos (180 segundos):

T=0s-30s:   Flujos 1-50 capturados → Procesados en lote al minuto 0:30
            • ct_dst_ltm para flujo 1 = 0
            • ct_dst_ltm para flujo 50 = 49

T=30s-60s:  Flujos 51-100 capturados → Procesados en lote al minuto 1:00
            • ct_dst_ltm para flujo 51 = 50 (flujos 1-50 en buffer)
            • ct_dst_ltm para flujo 100 = 99 (flujos 1-99 en buffer)

T=60s-90s:  Flujos 101-150 capturados → Procesados en lote al minuto 1:30
            • ct_dst_ltm para flujo 101 = 100 (pero buffer solo tiene 100, cuenta últimos 100)
            • ct_dst_ltm para flujo 150 = 99 (flujos 51-149 en buffer)

... (continúa hasta T=180s)
```

**Punto crítico:** El buffer de contexto mantiene **últimas 100 conexiones**, no últimas 30 segundos. Si el ataque genera más de 100 flujos, los más antiguos se eliminan del buffer, pero los nuevos siguen teniendo valores altos de `ct_*`.

**¿Cómo se identifica que flujos pertenecen al mismo ataque?**

**El sistema NO identifica explícitamente** que flujos pertenecen al mismo ataque. En su lugar:

1. **Cada flujo se clasifica independientemente** usando características básicas + contextuales.
2. **Las características contextuales (`ct_*`)** capturan el patrón de múltiples flujos similares.
3. **Si múltiples flujos tienen características similares y valores altos de `ct_*`**, todos se clasifican como el mismo tipo de ataque.

**Ejemplo:**
```
Ataque DoS: 20 flujos simultáneos desde diferentes puertos hacia 10.0.0.1:80

Flujo 1:  (192.168.1.100, 50001, 10.0.0.1, 80, TCP)
          ct_dst_ltm = 0  → Puede clasificarse como "Normal" (aún no hay contexto)
          
Flujo 2:  (192.168.1.100, 50002, 10.0.0.1, 80, TCP)
          ct_dst_ltm = 1  → Puede clasificarse como "Normal"
          
...

Flujo 10: (192.168.1.100, 50010, 10.0.0.1, 80, TCP)
          ct_dst_ltm = 9  → Clasificación: "DoS" (umbral superado)
          
Flujo 11-20: ct_dst_ltm = 10-19 → Todos clasificados como "DoS"
```

**Nota:** Los primeros flujos pueden clasificarse como "Normal" porque aún no hay suficiente contexto. Esto es **normal y esperado**.

**¿Qué es un flujo y qué lo diferencia de otro?**

Un **flujo** es un grupo de paquetes que comparten el mismo **5-tuple**:
```
Flujo = (saddr, sport, daddr, dport, proto)
```

**Si cambia CUALQUIER componente, es un NUEVO flujo:**

```
Flujo 1: (192.168.1.100, 50001, 10.0.0.1, 80, TCP)  ← Puerto origen: 50001
Flujo 2: (192.168.1.100, 50002, 10.0.0.1, 80, TCP)  ← Puerto origen: 50002 → DIFERENTE FLUJO
Flujo 3: (192.168.1.100, 50001, 10.0.0.1, 443, TCP) ← Puerto destino: 443 → DIFERENTE FLUJO
Flujo 4: (192.168.1.101, 50001, 10.0.0.1, 80, TCP)  ← IP origen diferente → DIFERENTE FLUJO
```

---

## 3. Pipeline General de Detección

El sistema Intrusion.Aware sigue este flujo para detectar ataques:

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRÁFICO DE RED                                │
│              (Paquetes en la interfaz)                          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS (Captura)                               │
│  • Lee paquetes de la interfaz                                  │
│  • Agrupa en flujos (5-tuple: saddr, sport, daddr, dport, proto)│
│  • Genera metadatos binarios de cada flujo                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RA PARSER (Extracción)                        │
│  • Convierte metadatos binarios a CSV (separado por |)          │
│  • Extrae 30 características básicas por flujo                  │
│  • Argus puede generar 175+ atributos (ver anexo en documentación)│
│  • Ejemplo: rate|saddr|sport|daddr|dport|proto|state|dur|...   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    TIMED BUFFER (Acumulación)                    │
│  • Acumula flujos durante 30 segundos (configurable)            │
│  • Procesa por lotes para análisis contextual                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER (Contexto)                   │
│  • Agrega características derivadas (service, is_sm_ips_ports)  │
│  • Calcula características contextuales (ct_*)                 │
│  • Mantiene buffer de 100 conexiones                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CLASIFICADOR ONNX                             │
│  • Modelo Binario: ¿Es ataque? (Sí/No)                          │
│  • Si es ataque → Modelo Multiclase: ¿Qué tipo?                │
│  • Usa umbrales configurables para confianza                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RESULTADO                                     │
│  • Ataque detectado → Base de datos + CSV + XMPP                │
│  • Tráfico normal → Solo CSV (logs/data.csv)                    │
└─────────────────────────────────────────────────────────────────┘
```

> **Para más detalles técnicos:** Consulta [Flujo de Captura y Clasificación](Flujo_Captura_Clasificacion.md) que explica cada componente con referencias a código. "Usa umbrales configurables para confianza" - debe indicarlos el grupo de datascience - no pueden ser definidos arbitrariamente por el desarrollador. 

---

## Análisis por Tipo de Ataque

Para cada tipo de ataque, este documento presenta:

1. **Definición y funcionamiento** según bibliografía
2. **Ejemplos prácticos y herramientas** utilizadas
3. **Pipeline de detección con Argus** (diagrama ASCII)
4. **Características detectadas** (básicas y contextuales)
5. **Contraste de las tres visiones** (Moustafa, Analistas, Hipótesis)
6. **Cambios potenciales a analizar**

---

## 1. FUZZERS

#### 4.1.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Fuzzers: Attempting to cause a program or network suspended by feeding it the randomly generated data."

**Mecánica del ataque:**
- Herramientas que envían **datos aleatorios o malformados** a aplicaciones
- Objetivo: Encontrar vulnerabilidades causando comportamiento inesperado
- Típicamente se dirigen a servicios HTTP, FTP, SSH
- Generan **alto volumen de tráfico** con patrones anómalos

**Herramientas comunes:**
- **Wfuzz**: Fuzzing de aplicaciones web (estamos usando)
- **Spike/Sulley**: Fuzzing de protocolos de red (considerar usar)
- **AFL (American Fuzzy Lop)**: Fuzzing de aplicaciones binarias
- **Burp Suite Intruder**: Fuzzing de aplicaciones web

#### 4.1.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Fuzzing Web                        │
│  Atacante ejecuta: wfuzz -c -z file,wordlist.txt http://target │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.1, dport=80        │
│           sbytes=1024, rate=50 pps, dur=0.5s, sttl=254          │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.1, dport=80        │
│           sbytes=2048, rate=48 pps, dur=0.5s, sttl=254          │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.1, dport=80        │
│           sbytes=512, rate=52 pps, dur=0.5s, sttl=254          │
│  ... (100 flujos similares)                                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • rate: 50 pps (alta)                                          │
│  • sbytes: Variable pero alto (1024-2048 bytes)                 │
│  • sttl: 254 (conexión remota)                                  │
│  • sloss: Significativa (algunos requests fallan)               │
│                                                                  │
│  Características contextuales (ct_*):                           │
│  • ct_srv_src = 100 (100 conexiones HTTP desde misma IP)        │
│  • ct_src_dport_ltm = 100 (100 intentos hacia puerto 80)        │
│  • ct_dst_ltm = 100 (100 conexiones hacia mismo destino)        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ✅ Múltiples conexiones desde misma IP origen                  │
│  ✅ Mismo servicio (HTTP) y mismo puerto destino                │
│  ✅ Tasa alta sostenida                                         │
│  ✅ Volumen variable pero alto                                  │
│  ✅ Pérdida significativa (requests rechazados)                 │
│                                                                  │
│  → CLASIFICACIÓN: FUZZERS                                       │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal?**
- Un solo flujo con alta tasa podría ser una descarga legítima
- **100 flujos** desde la misma IP hacia el mismo servicio con alta tasa = **Fuzzing sistemático**

#### 4.1.3 Características Detectadas

**Características básicas (Argus):**
- `rate`: Tasa alta (50+ pps)
- `sbytes`: Volumen alto y variable
- `sttl`: TTL alto (254 - conexión remota)
- `sloss`: Pérdida significativa
- `sload`: Carga alta origen

**Características contextuales (críticas):**
- `ct_srv_src`: Múltiples conexiones del mismo servicio desde misma IP
- `ct_src_dport_ltm`: Múltiples intentos hacia mismo puerto
- `ct_dst_ltm`: Múltiples conexiones hacia mismo destino

#### 4.1.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sbytes`, `rate`, `sttl`, `sloss` | `rate`, tiempo entre paquetes | `sbytes`, `rate`, `sttl`, `sloss` | ✅ `rate` (todos) |
| **Volumen** | Alto volumen origen | No mencionado | Alto volumen origen | ⚠️ Parcial |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples intentos | Buffer contextual | ✅ Requerida |

**Análisis:**
- **Consenso fuerte:** `rate` es crítica
- **Consenso parcial:** Volumen y pérdida importantes según Moustafa e hipótesis
- **Diferencia:** Analistas enfatizan patrones de comportamiento, bibliografía enfoca features técnicas

#### 4.1.5 Cambios Potenciales a Analizar

1. **Priorizar `rate` en explicaciones** (ya implementado, mejorar visibilidad)
2. **Incluir interpretación de patrones** ("tiempo entre paquetes muy corto indica fuzzing")
3. **Análisis de feature importance** para validar peso de `rate` vs `sbytes`

---

### 4.2 Analysis

#### 4.2.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Analysis: It contains different attacks of port scan, spam and html files penetrations."

**Mecánica del ataque:**
- **Escaneo de red** y análisis de vulnerabilidades
- Objetivo: Identificar servicios, puertos y sistemas expuestos
- Incluye: Port scanning, OS fingerprinting, detección de servicios
- Patrón: **Múltiples conexiones** a diferentes puertos/destinos

**Herramientas comunes:**
- **Nmap**: Escaneo de puertos y detección de servicios
- **Nessus/OpenVAS**: Escaneo de vulnerabilidades
- **Burp Suite/OWASP ZAP**: Análisis de aplicaciones web
- **Masscan/Zmap**: Escaneo rápido a gran escala

#### 4.2.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Escaneo de Puertos con Nmap        │
│  Atacante ejecuta: nmap -sS -sV 10.0.0.0/24                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.10, dport=22        │
│           state=SYN, dur=0.1s, spkts=3, dpkts=2                 │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.10, dport=80        │
│           state=SYN, dur=0.1s, spkts=3, dpkts=2                 │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.10, dport=443       │
│           state=SYN, dur=0.1s, spkts=3, dpkts=2                 │
│  Flujo 4: saddr=192.168.1.100, daddr=10.0.0.11, dport=22        │
│           state=SYN, dur=0.1s, spkts=3, dpkts=2                 │
│  ... (50 flujos similares)                                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • dur: Variable (0.1s para escaneo, 2.5s para análisis)        │
│  • spkts/dpkts: Patrón de escaneo (3/2 paquetes)                │
│  • state: Múltiples estados (SYN, EST)                           │
│  • rate: Alta tasa de escaneo                                    │
│                                                                  │
│  Características contextuales (ct_*):                           │
│  • ct_src_ltm = 50 (50 conexiones desde misma IP origen)        │
│  • ct_state_ttl = Variable (diferentes estados y TTL)            │
│  • ct_dst_ltm = Variable (múltiples destinos)                    │
│  • ct_src_dport_ltm = Variable (múltiples puertos destino)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ✅ Múltiples conexiones desde misma IP origen                  │
│  ✅ Múltiples puertos destino (escaneo sistemático)             │
│  ✅ Múltiples destinos (mapeo de red)                           │
│  ✅ Estados variados (SYN para escaneo, EST para análisis)     │
│  ✅ Duración variable (corta para escaneo, larga para análisis) │
│                                                                  │
│  → CLASIFICACIÓN: ANALYSIS                                       │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal?**
- Un solo escaneo de puerto puede parecer normal
- **50 escaneos** desde la misma IP hacia diferentes puertos/destinos = **Análisis sistemático**

#### 4.2.3 Características Detectadas

**Características básicas:**
- `dur`: Duración variable
- `spkts`/`dpkts`: Patrón de escaneo
- `state`: Múltiples estados (SYN, EST)
- `rate`: Alta tasa de escaneo

**Características contextuales (críticas):**
- `ct_src_ltm`: Múltiples conexiones desde misma IP origen
- `ct_state_ttl`: Conexiones con mismo estado y TTL
- `ct_dst_ltm`: Múltiples conexiones hacia diferentes destinos

#### 4.2.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `dur`, `spkts`, `dpkts`, `state` | `dur`, `rate`, simetría | `dur`, `spkts`, `dpkts`, `state` | ✅ `dur` (todos) |
| **Patrones** | Múltiples conexiones | Alta tasa, pocas completas | Múltiples conexiones | ✅ Alta |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples conexiones | Buffer contextual | ✅ Requerida |

#### 4.2.5 Cambios Potenciales a Analizar

1. **Mejorar detección de patrones de escaneo** (combinar `ct_src_ltm` con variabilidad de puertos)
2. **Distinguir escaneo rápido vs análisis profundo** (usar `dur` y `state`)

---

### 4.3 DoS (Denial of Service)

#### 4.3.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "DoS: A malicious attempt to make a server or a network resource unavailable to users, usually by temporarily interrupting or suspending the services of a host connected to the Internet."

**Mecánica del ataque:**
- **Saturación de recursos** mediante tráfico masivo
- Objetivo: Hacer servicios inaccesibles agotando recursos
- Patrón: **Alto volumen sostenido** de tráfico malicioso
- **Requiere ventana temporal crítica**: Un solo flujo puede parecer normal; múltiples flujos simultáneos indican DoS

**Herramientas comunes:**
- **hping3**: SYN flood, UDP flood
- **slowhttptest**: Slow HTTP attacks (Slowloris)
- **LOIC/HOIC**: Ataques de inundación HTTP
- **Siege/Apache Bench**: Load testing usado para DoS

#### 4.3.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: SYN Flood Attack                   │
│  Múltiples atacantes coordinados saturan servidor web            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.1, dport=80         │
│           rate=50 pps, dur=5s, sbytes=10240, sloss=10%          │
│  Flujo 2: saddr=192.168.1.101, daddr=10.0.0.1, dport=80         │
│           rate=45 pps, dur=5s, sbytes=9216, sloss=12%           │
│  Flujo 3: saddr=192.168.1.102, daddr=10.0.0.1, dport=80         │
│           rate=55 pps, dur=5s, sbytes=11264, sloss=8%            │
│  ... (20 flujos simultáneos hacia mismo destino)                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • rate: Alta (45-55 pps por flujo)                             │
│  • sbytes: Alto volumen por flujo                                │
│  • sloss: Pérdida significativa (servidor saturado)             │
│  • dur: Prolongada (5s sostenido)                               │
│                                                                  │
│  Características contextuales (ct_*) - CRÍTICAS:                │
│  • ct_dst_ltm = 20 (20 conexiones hacia 10.0.0.1)              │
│  • ct_srv_dst = 20 (todas hacia servicio HTTP)                  │
│  • ct_dst_src_ltm = Variable (diferentes orígenes)               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ⚠️ CRÍTICO: Un solo flujo puede parecer normal                 │
│  ⚠️ Pero 20 flujos simultáneos hacia mismo destino = DoS        │
│                                                                  │
│  ✅ Múltiples flujos simultáneos hacia mismo destino            │
│  ✅ Mismo servicio (HTTP)                                        │
│  ✅ Alta tasa sostenida                                         │
│  ✅ Pérdida masiva (servidor saturado)                          │
│  ✅ Volumen masivo total                                         │
│                                                                  │
│  → CLASIFICACIÓN: DoS                                            │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal crítica?**
- **Un solo flujo** con alta tasa → Podría ser descarga legítima grande
- **20 flujos simultáneos** hacia mismo destino con alta tasa → **DoS coordinado**

#### 4.3.3 Características Detectadas

**Características básicas:**
- `sbytes`: Volumen masivo
- `rate`: Tasa alta sostenida
- `sloss`: Pérdida masiva
- `dur`: Duración prolongada
- `sload`: Carga alta origen

**Características contextuales (críticas):**
- `ct_dst_ltm`: **CRÍTICO** - Múltiples flujos hacia mismo destino
- `ct_srv_dst`: **CRÍTICO** - Saturación de servicio específico
- `ct_dst_src_ltm`: Útil para detectar persistencia

#### 4.3.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sbytes`, `rate`, `sloss`, `dur` | `dur`, `rate`, pérdida | `sbytes`, `rate`, `sloss`, `dur` | ✅ Perfecto |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples flujos simultáneos | Buffer contextual | ✅ Crítica |
| **Patrón** | Alto volumen sostenido | Muchos paquetes en poco tiempo | Alto volumen sostenido | ✅ Perfecto |

**Análisis:**
- **Coincidencia perfecta** entre las tres fuentes
- DoS es el ejemplo más claro de por qué necesitamos ventanas temporales

#### 4.3.5 Cambios Potenciales a Analizar

1. **Umbrales dinámicos** para `ct_dst_ltm` según tipo de servicio
2. **Detección de Slow HTTP attacks** (baja tasa pero muchas conexiones simultáneas)

---

### 4.4 Exploits

#### 4.4.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Exploits: The attacker knows of a security problem within an operating system or a piece of software and leverages that knowledge by exploiting the vulnerability."

**Mecánica del ataque:**
- **Aprovechamiento de vulnerabilidades** conocidas
- Objetivo: Comprometer la seguridad del sistema
- Ejemplos: Buffer overflow, SQL injection, code injection
- Patrón: **Payloads específicos** enviados a servicios vulnerables

**Herramientas comunes:**
- **Metasploit Framework**: Framework de explotación
- **SQLMap**: Explotación de SQL Injection
- **Exploit-DB scripts**: Scripts de explotación públicos
- **Custom exploits**: Exploits desarrollados específicamente

#### 4.4.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: SQL Injection con SQLMap           │
│  Atacante ejecuta: sqlmap -u "http://target/login.php?id=1"     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.1, dport=80         │
│           sbytes=512, rate=2 pps, dur=1.0s, sttl=254             │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.1, dport=80         │
│           sbytes=1024, rate=2 pps, dur=1.5s, sttl=254             │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.1, dport=80         │
│           sbytes=2048, rate=2 pps, dur=2.0s, sttl=254             │
│  ... (10 flujos con payloads crecientes)                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • sbytes: Alto y creciente (payloads de explotación)            │
│  • rate: Puede ser baja (exploits cuidadosos) o alta (automatizados)│
│  • sttl: Muy alto (254 - conexión remota)                       │
│  • smeansz: Tamaño medio alto (payloads grandes)                │
│                                                                  │
│  Características contextuales (ct_*):                           │
│  • ct_state_ttl: Nuevas conexiones (estado inicial)             │
│  • ct_srv_dst: Múltiples intentos hacia mismo servicio         │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ✅ Payloads grandes (sbytes alto)                              │
│  ✅ TTL muy alto (conexión remota)                              │
│  ✅ Nuevas conexiones (ct_state_ttl)                            │
│  ✅ Desbalance origen/destino (payloads grandes, respuestas pequeñas)│
│                                                                  │
│  → CLASIFICACIÓN: EXPLOITS                                       │
└─────────────────────────────────────────────────────────────────┘
```

**Nota:** Exploits pueden detectarse en un solo flujo, pero el contexto ayuda a identificar patrones repetitivos.

#### 4.4.3 Características Detectadas

**Características básicas:**
- `sbytes`: Volumen extremo (payloads grandes)
- `rate`: Variable (baja para cuidadosos, alta para automatizados)
- `sttl`: Muy alto (254 - remoto)
- `smeansz`: Tamaño medio alto

**Características contextuales:**
- `ct_state_ttl`: Nuevas conexiones
- `ct_srv_dst`: Múltiples intentos hacia mismo servicio

#### 4.4.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sbytes`, `rate`, `sttl` | `spkts`, `dpkts`, `rate` baja | `sbytes`, `rate` alta, `sttl` | ⚠️ Discrepancia en `rate` |
| **Volumen** | Payloads grandes | Payloads grandes | Payloads grandes | ✅ Coincidencia |
| **Ventana temporal** | No crítica | No mencionada | No crítica | ⚠️ No requerida |

**Análisis:**
- **Discrepancia importante:** Analistas observaron "tasa baja" mientras hipótesis sugiere "tasa alta"
- **Explicación:** Ambos patrones válidos (pocos paquetes grandes vs muchos paquetes pequeños)

#### 4.4.5 Cambios Potenciales a Analizar

1. **Considerar ambos patrones de `rate`** (baja con payloads grandes vs alta con payloads pequeños)
2. **Análisis de payloads** (inspección de contenido, no solo métricas de flujo)

---

### 4.5 Generic (Fuerza Bruta)

#### 4.5.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Generic: A technique works against all blockciphers (with a given block and key size), without consideration about the structure of the block-cipher."

**Mecánica del ataque:**
- **Ataques de fuerza bruta** y autenticaciones repetitivas
- Objetivo: Obtener credenciales mediante prueba sistemática
- Típicamente: SSH, FTP, servicios de autenticación
- Patrón: **Múltiples intentos** con diferentes credenciales

**Herramientas comunes:**
- **Hydra**: Fuerza bruta de múltiples protocolos
- **Medusa**: Fuerza bruta paralela
- **John the Ripper**: Fuerza bruta de hashes
- **Ncrack**: Fuerza bruta de red

#### 4.5.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Fuerza Bruta SSH con Hydra         │
│  Atacante ejecuta: hydra -l admin -P passwords.txt ssh://target  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.1, dport=22         │
│           spkts=10, rate=5 pps, dur=2.0s, state=EST              │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.1, dport=22         │
│           spkts=10, rate=5 pps, dur=2.0s, state=EST              │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.1, dport=22         │
│           spkts=10, rate=5 pps, dur=2.0s, state=EST              │
│  ... (100 intentos similares)                                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • spkts: Alto (múltiples paquetes por intento)                 │
│  • rate: Sostenida (intentos regulares)                         │
│  • dur: Similar en cada intento (patrón repetitivo)             │
│  • service: SSH (servicio específico)                            │
│                                                                  │
│  Características contextuales (ct_*) - CRÍTICAS:               │
│  • ct_src_dport_ltm = 100 (100 intentos desde misma IP hacia puerto 22)│
│  • ct_srv_src = 100 (todos hacia servicio SSH)                  │
│  • ct_dst_ltm = 100 (todos hacia mismo destino)                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ⚠️ CRÍTICO: Un solo intento puede parecer normal               │
│  ⚠️ Pero 100 intentos desde misma IP hacia mismo puerto = Fuerza bruta│
│                                                                  │
│  ✅ Múltiples intentos repetitivos desde misma IP               │
│  ✅ Mismo servicio (SSH) y mismo puerto destino                 │
│  ✅ Patrón repetitivo (mismo patrón de conexión)                │
│  ✅ Tasa sostenida (intentos regulares)                          │
│                                                                  │
│  → CLASIFICACIÓN: GENERIC                                        │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal crítica?**
- **Un solo intento** de autenticación → Normal
- **100 intentos** desde misma IP hacia mismo puerto → **Fuerza bruta sistemática**

#### 4.5.3 Características Detectadas

**Características básicas:**
- `spkts`: Alto volumen de intentos
- `rate`: Tasa sostenida
- `service`: Servicios específicos (SSH, FTP)
- `dur`: Patrón repetitivo

**Características contextuales (críticas):**
- `ct_srv_src`: **CRÍTICO** - Múltiples intentos desde misma IP
- `ct_src_dport_ltm`: **CRÍTICO** - Intentos repetitivos hacia mismo puerto
- `ct_dst_ltm`: Útil para detectar múltiples intentos hacia mismo objetivo

#### 4.5.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `spkts`, `rate`, `service` | `rate`, consulta baja en tiempo | `spkts`, `rate`, `service` | ✅ Alta |
| **Patrones** | Repetitivos y sistemáticos | Repetitivos y sistemáticos | Repetitivos y sistemáticos | ✅ Perfecto |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples intentos | Buffer contextual | ✅ Crítica |

#### 4.5.5 Cambios Potenciales a Analizar

1. **Umbrales por servicio** (SSH puede tener más intentos legítimos que FTP)
2. **Detección de patrones de timing** (intentos muy regulares indican automatización)

---

### 4.6 Reconnaissance

#### 4.6.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Reconnaissance: Contains all Strikes that can simulate attacks that gather information."

**Mecánica del ataque:**
- **Escaneo de puertos**, OS fingerprinting, detección de servicios
- Objetivo: Mapear infraestructura antes de atacar
- Patrón: **Sistemático** y **múltiples destinos/puertos**
- **Requiere ventana temporal**: Un solo escaneo puede parecer normal; múltiples escaneos indican reconnaissance

**Herramientas comunes:**
- **Nmap**: Escaneo de puertos más popular
- **Masscan**: Escaneo ultra-rápido
- **Zmap**: Escaneo de internet a gran escala
- **Shodan/Censys**: Motores de búsqueda de dispositivos

#### 4.6.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Escaneo Sistemático con Nmap      │
│  Atacante ejecuta: nmap -sS -sV 10.0.0.0/24                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.10, dport=22       │
│           dur=0.5s, spkts=3, dpkts=2                            │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.10, dport=80       │
│           dur=0.5s, spkts=3, dpkts=2                            │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.10, dport=443      │
│           dur=0.5s, spkts=3, dpkts=2                            │
│  Flujo 4: saddr=192.168.1.100, daddr=10.0.0.11, dport=22       │
│           dur=0.5s, spkts=3, dpkts=2                            │
│  ... (50 flujos hacia diferentes destinos y puertos)            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • dur: Corta (0.5s para escaneo)                               │
│  • spkts/dpkts: Patrón de escaneo (3/2 paquetes)                │
│  • rate: Alta tasa de escaneo                                   │
│  • sttl/dttl: Fingerprinting (análisis de TTL)                   │
│                                                                  │
│  Características contextuales (ct_*) - CRÍTICAS:                │
│  • ct_src_ltm = 50 (50 conexiones desde misma IP origen)        │
│  • ct_src_dport_ltm = Variable (múltiples puertos destino)       │
│  • ct_dst_ltm = Variable (múltiples destinos)                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ⚠️ CRÍTICO: Un solo escaneo puede parecer normal               │
│  ⚠️ Pero 50 escaneos desde misma IP = Reconnaissance sistemático│
│                                                                  │
│  ✅ Múltiples conexiones desde misma IP origen                  │
│  ✅ Múltiples puertos destino (escaneo sistemático)             │
│  ✅ Múltiples destinos (mapeo de red)                           │
│  ✅ Patrón sistemático (escaneo organizado)                     │
│                                                                  │
│  → CLASIFICACIÓN: RECONNAISSANCE                                 │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal crítica?**
- **Un solo escaneo** de puerto → Normal
- **50 escaneos** desde misma IP hacia diferentes puertos/destinos → **Reconnaissance sistemático**

#### 4.6.3 Características Detectadas

**Características básicas:**
- `sport`/`dport`: Puertos variables
- `dur`: Duración corta
- `rate`: Alta tasa de escaneo
- `sttl`/`dttl`: Fingerprinting
- `spkts`/`dpkts`: Patrón de escaneo

**Características contextuales (críticas):**
- `ct_src_ltm`: **CRÍTICO** - Origen de escaneo sistemático
- `ct_src_dport_ltm`: Útil - Escaneo de puertos específicos
- `ct_dst_ltm`: Variable - Múltiples destinos

#### 4.6.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sport`, `dport`, `sttl`, `dttl` | `dur`, `rate`, captura normal | Múltiples puertos, `ct_dst_ltm` | ✅ Alta |
| **Patrones** | Múltiples destinos/puertos | Muchos destinos, muchos puertos | Múltiples destinos/puertos | ✅ Perfecto |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples conexiones | Buffer contextual | ✅ Crítica |

#### 4.6.5 Cambios Potenciales a Analizar

1. **Distinguir escaneo rápido vs lento** (usar `rate` y `dur`)
2. **Detección de escaneo distribuido** (múltiples orígenes coordinados)

---

### 4.7 Shellcode

#### 4.7.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Shellcode: A small piece of code used as the payload in the exploitation of software vulnerability."

**Mecánica del ataque:**
- **Inyección de código malicioso** ejecutable
- Objetivo: Obtener shell remoto o ejecutar comandos
- Patrón: **Payloads de código** seguidos de **respuestas del sistema**
- Características: Alta variabilidad en tamaños de paquetes

**Herramientas comunes:**
- **Metasploit Framework**: Generación de shellcode
- **msfvenom**: Generador de payloads
- **Shell-Storm**: Base de datos de shellcode
- **Custom shellcode**: Shellcode desarrollado específicamente

#### 4.7.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Inyección de Shellcode             │
│  Atacante explota buffer overflow e inyecta shellcode           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1 (Inyección):                                            │
│    saddr=192.168.1.100, daddr=10.0.0.1, dport=80               │
│    sbytes=1048576, dbytes=512, dur=2.0s                         │
│    sload=524288 bps, dload=256 bps                              │
│    smeansz=1024, dmeansz=256                                     │
│                                                                  │
│  Flujo 2 (Shell reverso):                                        │
│    saddr=10.0.0.1, daddr=192.168.1.100, sport=4444             │
│    sbytes=1024, dbytes=2048, dur=300.0s                         │
│    sload=512 bps, dload=1024 bps                                │
│    smeansz=512, dmeansz=1024                                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • sbytes/dbytes: Alto en inyección, variable en shell           │
│  • sload/dload: Alta carga en ambos sentidos                    │
│  • smeansz/dmeansz: Tamaños variables                           │
│  • rate: Alta (gran cantidad de paquetes)                        │
│                                                                  │
│  Características contextuales (ct_*):                           │
│  • ct_dst_src_ltm: Persistencia de comunicación                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ✅ Payloads de código grandes (sbytes alto en inyección)       │
│  ✅ Respuestas del sistema (dbytes variable)                    │
│  ✅ Alta variabilidad en tamaños (smeansz/dmeansz variables)     │
│  ✅ Patrón de inyección seguido de comunicación bidireccional    │
│                                                                  │
│  → CLASIFICACIÓN: SHELLCODE                                      │
└─────────────────────────────────────────────────────────────────┘
```

**Nota:** Shellcode puede detectarse en un solo flujo, pero el contexto ayuda a identificar la secuencia completa.

#### 4.7.3 Características Detectadas

**Características básicas:**
- `sbytes`/`dbytes`: Payloads y respuestas
- `sload`/`dload`: Carga alta en ambos sentidos
- `smeansz`/`dmeansz`: Tamaños variables
- `rate`: Alta tasa de paquetes

**Características contextuales:**
- `ct_dst_src_ltm`: Persistencia de comunicación

#### 4.7.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sbytes`, `dbytes` | `sload`, `dload`, `smean`, `dmean` | `sbytes`, `dbytes` | ✅ Perfecto |
| **Variabilidad** | Alta variabilidad | Tamaños variables | Alta variabilidad | ✅ Perfecto |
| **Ventana temporal** | No crítica | No mencionada | No crítica | ⚠️ No requerida |

#### 4.7.5 Cambios Potenciales a Analizar

1. **Detección de secuencias** (inyección seguida de shell reverso)
2. **Análisis de patrones de comunicación** (comando y control)

---

### 4.8 Worms

#### 4.8.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Worms: Attacker replicates itself in order to spread to other computers. Often, it uses a computer network to spread itself, relying on security failures on the target computer to access it."

**Mecánica del ataque:**
- **Propagación automática** por la red
- Objetivo: Infectar múltiples sistemas (propagación en cadena)
- Patrón: **Propagación rápida** con **alta variabilidad**
- **Requiere ventana temporal**: Un solo flujo puede parecer normal; múltiples flujos a diferentes destinos indican worm

**Herramientas comunes:**
- **Worm simulators**: Para investigación y testing
- **Custom worm code**: Worms desarrollados específicamente

#### 4.8.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Propagación de Worm                │
│  Sistema infectado propaga automáticamente a múltiples destinos  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=10.0.0.5, daddr=10.0.0.10, rate=100 pps        │
│           dur=2s, sttl=254, sbytes=20480                        │
│  Flujo 2: saddr=10.0.0.5, daddr=10.0.0.11, rate=95 pps         │
│           dur=2s, sttl=254, sbytes=19456                        │
│  Flujo 3: saddr=10.0.0.5, daddr=10.0.0.12, rate=105 pps        │
│           dur=2s, sttl=254, sbytes=21504                        │
│  ... (15 flujos hacia diferentes destinos)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • rate: Extrema (95-105 pps)                                   │
│  • dur: Corta (2s - propagación rápida)                         │
│  • sttl: Muy alto (254 - conexión remota)                       │
│  • sbytes/dbytes: Variables (diferentes tamaños)                │
│  • smeansz/dmeansz: Alta variabilidad                            │
│                                                                  │
│  Características contextuales (ct_*) - CRÍTICAS:                │
│  • ct_src_ltm = 15 (15 conexiones desde 10.0.0.5)               │
│  • ct_dst_ltm = Variable (múltiples destinos)                    │
│  • ct_dst_src_ltm = Variable (diferentes pares IP)               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ⚠️ CRÍTICO: Un solo flujo puede parecer normal                 │
│  ⚠️ Pero 15 flujos desde misma IP hacia diferentes destinos = Worm│
│                                                                  │
│  ✅ Múltiples conexiones desde misma IP origen                  │
│  ✅ Múltiples destinos (propagación automática)                  │
│  ✅ Tasa extrema, corta duración (propagación rápida)            │
│  ✅ Alta variabilidad (diferentes tamaños y patrones)            │
│                                                                  │
│  → CLASIFICACIÓN: WORMS                                          │
└─────────────────────────────────────────────────────────────────┘
```

**¿Por qué requiere ventana temporal crítica?**
- **Un solo flujo** hacia un destino → Podría ser conexión legítima
- **15 flujos** desde misma IP hacia diferentes destinos → **Propagación automática de worm**

#### 4.8.3 Características Detectadas

**Características básicas:**
- `rate`: Tasa extrema, corta duración
- `dur`: Corta (propagación rápida)
- `sttl`: Muy alto (254 - remoto)
- `sbytes`/`dbytes`: Variables
- `smeansz`/`dmeansz`: Alta variabilidad

**Características contextuales (críticas):**
- `ct_src_ltm`: **CRÍTICO** - Múltiples conexiones desde sistema infectado
- `ct_dst_ltm`: Variable - Múltiples destinos
- `ct_dst_src_ltm`: Variable - Diferentes pares IP

#### 4.8.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `rate`, `dur`, `sttl` | Diferencia de paquetes, peso, carga | `rate`, `dur`, `sttl` | ✅ Perfecto |
| **Propagación** | Rápida, múltiples destinos | Alta cantidad de datos destino | Rápida, múltiples destinos | ✅ Perfecto |
| **Ventana temporal** | Buffer de 100 conexiones | Múltiples conexiones | Buffer contextual | ✅ Crítica |

#### 4.8.5 Cambios Potenciales a Analizar

1. **Detección de propagación exponencial** (nuevos orígenes infectados)
2. **Análisis de patrones temporales** (propagación muy rápida vs lenta)

---

### 4.9 Backdoor

#### 4.9.1 Definición y Funcionamiento

**Bibliografía (Moustafa et al., 2015):**
> "Backdoors: A technique in which a system security mechanism is bypassed stealthily to access a computer or its data."

**Mecánica del ataque:**
- **Puertas traseras** para acceso no autorizado persistente
- Objetivo: Mantener acceso remoto encubierto
- Patrón: **Comunicación encubierta** y **persistente**
- Características: Bajo perfil, comunicación estable

**Herramientas comunes:**
- **Netcat (nc)**: Backdoor simple
- **Socat**: Backdoor sofisticado
- **Metasploit Meterpreter**: Backdoor avanzado
- **SSH backdoors**: Backdoors usando SSH
- **Web shells**: Backdoors web (PHP, ASP, JSP)

#### 4.9.2 Pipeline de Detección con Argus

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCENARIO: Backdoor Netcat                    │
│  Sistema comprometido con listener en puerto 4444                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS CAPTURA                                 │
│  Flujo 1: saddr=192.168.1.100, daddr=10.0.0.1, dport=4444       │
│           state=EST, dur=300.0s, sttl=254                       │
│           sloss=0%, sbytes=5120, dbytes=10240                   │
│  Flujo 2: saddr=192.168.1.100, daddr=10.0.0.1, dport=4444       │
│           state=EST, dur=600.0s, sttl=254                       │
│           sloss=0%, sbytes=10240, dbytes=20480                  │
│  Flujo 3: saddr=192.168.1.100, daddr=10.0.0.1, dport=4444       │
│           state=EST, dur=900.0s, sttl=254                       │
│           sloss=0%, sbytes=15360, dbytes=30720                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE ENRICHER                              │
│  Características básicas detectadas:                             │
│  • sttl: Muy alto (254 - conexión remota)                       │
│  • state: EST (conexión establecida, persistente)               │
│  • dur: Prolongada (comunicación continua)                      │
│  • sloss: Bajo (comunicación estable, sin pérdida)               │
│  • Desbalance moderado origen/destino (comando y control)       │
│                                                                  │
│  Características contextuales (ct_*):                           │
│  • ct_state_ttl: Estado inicial, nuevo (nueva conexión backdoor) │
│  • ct_dst_src_ltm: Persistencia de comunicación entre mismas IPs│
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PATRÓN DETECTADO                              │
│  ✅ TTL muy alto (conexión remota)                              │
│  ✅ Comunicación encubierta (bajo volumen, bajo perfil)          │
│  ✅ Persistencia (comunicación continua)                         │
│  ✅ Sin pérdida (comunicación estable)                           │
│  ✅ Estado establecido (EST)                                     │
│                                                                  │
│  → CLASIFICACIÓN: BACKDOOR                                      │
└─────────────────────────────────────────────────────────────────┘
```

**Nota:** Backdoor puede detectarse parcialmente en un solo flujo, pero el contexto ayuda a identificar persistencia.

#### 4.9.3 Características Detectadas

**Características básicas:**
- `sttl`: Muy alto (254 - remoto)
- `state`: EST (persistente)
- `sloss`: Bajo (comunicación estable)
- `sbytes`/`dbytes`: Bajo volumen
- `rate`: Baja tasa

**Características contextuales:**
- `ct_state_ttl`: Nuevas conexiones persistentes
- `ct_dst_src_ltm`: **CRÍTICO** - Persistencia de comunicación encubierta

#### 4.9.4 Contraste de las Tres Visiones

| Aspecto | Moustafa et al. | Analistas SOC | Hipótesis Teóricas | Consenso |
|---------|----------------|---------------|-------------------|----------|
| **Features críticas** | `sttl`, `state`, `sloss` | Envío sin respuesta, persistencia | `sttl`, comunicación encubierta | ✅ Alta |
| **Persistencia** | Comunicación encubierta | Persistencia/paquetes por segundo | Comunicación encubierta | ✅ Perfecto |
| **Ventana temporal** | Parcial | No mencionada | Parcial | ⚠️ Parcial |

#### 4.9.5 Cambios Potenciales a Analizar

1. **Detección de puertos no estándar** (backdoors en puertos inusuales)
2. **Análisis de patrones de comunicación** (comando y control encubierto)

---

## 5. Resumen Comparativo: Ventanas Temporales

### Ataques que Requieren Ventana Temporal

| Tipo de Ataque | ¿Requiere Ventana? | Características Contextuales Críticas | Razón |
|----------------|-------------------|----------------------------------------|-------|
| **DoS** | ✅ **SÍ - CRÍTICO** | `ct_dst_ltm`, `ct_srv_dst` | Múltiples flujos simultáneos hacia mismo destino |
| **Reconnaissance** | ✅ **SÍ - CRÍTICO** | `ct_src_ltm`, `ct_src_dport_ltm` | Múltiples escaneos desde mismo origen |
| **Worms** | ✅ **SÍ - CRÍTICO** | `ct_src_ltm`, `ct_dst_ltm` | Propagación a múltiples destinos |
| **Generic** | ✅ **SÍ - CRÍTICO** | `ct_srv_src`, `ct_src_dport_ltm` | Múltiples intentos de fuerza bruta |
| **Fuzzers** | ✅ **SÍ** | `ct_srv_src`, `ct_src_dport_ltm` | Múltiples intentos de fuzzing |
| **Analysis** | ✅ **SÍ** | `ct_state_ttl`, `ct_dst_ltm` | Múltiples conexiones de escaneo |
| **Backdoor** | ⚠️ **PARCIAL** | `ct_state_ttl`, `ct_dst_src_ltm` | Persistencia de comunicación |
| **Exploits** | ❌ **NO** | `ct_state_ttl` | Puede detectarse en un solo flujo |
| **Shellcode** | ❌ **NO** | `ct_dst_src_ltm` | Puede detectarse en un solo flujo |

### Implementación de Ventanas Temporales

**Referencia Moustafa et al. (2015):**
> "The features 36-47 of Table VI are intended to sort accordingly with the last time feature to capture similar characteristics of the connection records for each 100 connections sequentially ordered."

**Nuestra implementación:**
- Buffer de contexto de **100 conexiones** (configurable)
- Características `ct_*` calculadas sobre el buffer completo
- Procesamiento por lotes cada **30 segundos** (configurable)
- Mantiene orden temporal implícito (FIFO)

**Diferencia con Moustafa:**
- **Moustafa**: Ordena explícitamente por `ltime` (último tiempo)
- **Nuestra implementación**: Buffer FIFO que mantiene las últimas 100 conexiones procesadas

> **Para detalles técnicos de implementación:** Consulta [Flujo de Captura y Clasificación](Flujo_Captura_Clasificacion.md).

---

## 6. Conclusiones y Recomendaciones

### Coincidencias entre Fuentes

1. **Features temporales son críticas**: `dur` y `rate` fueron identificadas como relevantes por las tres fuentes
2. **Ventanas temporales son esenciales**: Ataques como DoS, Reconnaissance, Worms y Generic requieren análisis de múltiples flujos
3. **Características contextuales (`ct_*`) son fundamentales**: Detectan patrones que un solo flujo no puede revelar

### Discrepancias Identificadas

1. **Exploits - Tasa de tráfico**:
   - Hipótesis teóricas: Tasa muy alta
   - Analistas observaron: Tasa de tráfico baja
   - **Explicación**: Ambos patrones son válidos (pocos paquetes grandes vs muchos paquetes pequeños)

2. **Ordenamiento temporal**:
   - Moustafa: Ordena explícitamente por `ltime`
   - Nuestra implementación: Buffer FIFO
   - **Recomendación**: Considerar ordenamiento explícito por `ltime` para mayor precisión

### Recomendaciones de Mejora

1. **Ordenamiento explícito por `ltime`**: Alinear completamente con metodología Moustafa
2. **Tamaño de buffer configurable**: Ya implementado, considerar ajuste dinámico
3. **Análisis de feature importance**: Validar qué features son más importantes según el modelo
4. **Refinamiento de explicaciones**: Priorizar features temporales e incluir interpretaciones de características contextuales

---

## 7. Anexos

### A. Generación de Dataset Etiquetado

Esta sección explica cómo generar un dataset etiquetado para entrenar modelos de IA, **sin usar el sistema Intrusion.Aware**. Este proceso es manual y requiere herramientas externas (Argus, scripts de procesamiento).

> **Nota:** Esta información es útil para investigadores que quieren generar sus propios datasets. Para usar el sistema en producción, consulta el [Anexo B](#b-ejecución-en-producción-consulta-al-modelo).

#### A.1 Proceso Completo: De Tráfico a Dataset Etiquetado

**Objetivo:** Crear una "sábana de datos" etiquetada para entrenar modelos de IA.

**Proceso paso a paso:**

1. **Captura de tráfico con ataques controlados**
2. **Procesamiento con Argus**
3. **Enriquecimiento contextual (simulación del buffer)**
4. **Heurística de deduplicación**
5. **Estructura final del dataset**

> **Para el contenido completo de esta sección:** Las secciones "Parte A: Generación de Dataset Etiquetado" y "Parte B: Ejecución en Producción" que aparecían anteriormente en el documento han sido movidas a este anexo. El contenido detallado se mantiene igual, pero ahora está organizado como material de referencia al final del documento.

### B. Ejecución en Producción: Consulta al Modelo

Esta sección explica cómo funciona el sistema Intrusion.Aware en producción para detectar ataques en tiempo real.

> **Nota:** El sistema Intrusion.Aware **ya implementa todo el proceso automáticamente**. Esta sección es solo para entender cómo funciona internamente.

#### B.1 Cómo Funciona el Sistema en Producción

El sistema procesa flujos automáticamente:
1. **Flujos llegan** → Se acumulan en Timed Buffer (30 segundos)
2. **Cada 30s** → Se procesan todos los flujos del lote
3. **Para cada flujo:**
   - Se calculan `ct_*` sobre buffer GLOBAL (últimas 100 conexiones)
   - Se prepara vector de 39 características
   - Se consulta modelo binario (de a uno)
   - Si es ataque → Se consulta modelo multiclase (de a uno)
   - Si supera umbrales → Se guarda y publica
   - Se actualiza buffer GLOBAL

> **Para detalles técnicos completos:** Consulta [Flujo de Captura y Clasificación](Flujo_Captura_Clasificacion.md) que explica cada componente con referencias a código.

---

## Referencias

1. **Moustafa, N., & Slay, J. (2015).** UNSW-NB15: A comprehensive data set for network intrusion detection systems. *IEEE Military Communications and Information Systems Conference (MilCIS)*.

2. **Reporte de Validación Intrusion.Aware (Octubre 2025).** Feedback de analistas SOC de CSIRT y REUNA.

3. **Flujo de Captura y Clasificación.** Documento técnico detallado del pipeline completo: [Flujo_Captura_Clasificacion.md](Flujo_Captura_Clasificacion.md)

---

**Documento preparado por:** Equipo Intrusion.Aware  
**Fecha:** Diciembre 2025  
**Versión:** 2.0 (Reorganizado)
