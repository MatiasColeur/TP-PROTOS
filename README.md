![porotos](/img/porotos.jpg)

---

# POROTOS — Servidor SOCKS5 No Bloqueante

Este proyecto implementa un **servidor proxy SOCKS5** según los RFC **1928** y **1929**, utilizando **I/O no bloqueante**, una **máquina de estados**, y un **multiplexor selector** para manejar **múltiples clientes concurrentes** de forma eficiente.
El servidor soporta:

* Autenticación **usuario/contraseña** (RFC 1929).
* Comandos **CONNECT** hacia IPv4, IPv6 o FQDN.
* Reintentos ante fallas de conexión.
* Registro de accesos (logging por usuario).
* Métricas internas (bytes transferidos, conexiones históricas, concurrentes, etc.).
* Interfaz de **administración y monitoreo en tiempo de ejecución** mediante una **API TCP propia**, como requiere el enunciado del TP. 

---

## Cómo está organizado el repo

```
.
├── README.md                # Este archivo
├── include/                 # Headers compartidos por server/API/clients
├── src/
│   ├── server/              # Lógica del SOCKS5 y su estado
│   ├── api/                 # API de admin/metrics que expone el TP
│   ├── client/              # Clientes de prueba (ipv4/ipv6/dns, admin, stress)
│   └── shared/              # Utilidades comunes (parsers, buffers, logs, etc.)
├── bin/                     # Binarios generados por make
├── obj/                     # Objetos intermedios
├── log/                     # Logs (ej: bytes transferidos)
└── users.csv                # Usuarios base de la API (admin, etc.)
```

---

## Requisitos previos IMPORTANTES

### 1. La **API debe estar corriendo antes de iniciar el servidor SOCKS5**

La API es el módulo de configuración/monitoreo del sistema.
El servidor se comunica con ella para:

* obtener usuarios válidos,
* agregar nuevos usuarios en tiempo de ejecución,
* actualizar parámetros,
* consultar métricas.

### 2. Archivo obligatorio: `users.csv`

Debe existir un archivo `users.csv` en la raíz del proyecto, con al menos el usuario administrador:

```
admin,fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b
```

(user:admin, pass:admin)
Sin este archivo, la API no podrá levantar correctamente la base de usuarios. No se debe modificar el archivo `users.csv` durante la ejecución de la api ya que esta tiene una copia en memoria.

---

## Dependencias


* **gcc**
* **make**
* **openssl**
  (usado únicamente para funcionalidades auxiliares permitidas por la cátedra y con licencia OSI aprobada)

---

## Compilación

```bash
$ make clean all
```

---

## Ejecución y clientes de prueba

Todos los binarios soportan `-h` para ver opciones completas.

---

### 1) Admin API

**Previo a ejecutar el server**

```bash
./bin/api [OPTIONS]
```

**Ejemplos**

```bash
./bin/api
./bin/api -l ::1 -p 8080
./bin/api -l :: -p 8080
```

---

### 2) Servidor SOCKS5


```bash
./bin/socks5 [OPTIONS]
```

**Ejemplos**

```bash
./bin/socks5
./bin/socks5 -L ::1 -P 8080
./bin/socks5 -l ::1 -p 1080 -L ::1 -P 8080 -u maxi:chiate
```

---

## Clientes SOCKS5 (smoke tests)

### Cliente IPv4


```bash
./bin/client_ipv4 [OPTIONS]
```

**Ejemplo**

```bash
./bin/client_ipv4 -l 127.0.0.1 -p 1080
```

---

### Cliente IPv6


```bash
./bin/client_ipv6 [OPTIONS]
```

**Ejemplo**

```bash
./bin/client_ipv6 -l ::1 -p 1080
```

---

### Cliente DNS (FQDN)


```bash
./bin/client_dns [OPTIONS]
```

**Ejemplo**

```bash
./bin/client_dns -l 127.0.0.1 -p 1080
```

---

## Métricas y monitoreo

### Cliente de métricas (vía SOCKS → API)

```bash
./bin/admin_metrics [OPCION] [usuario]
```

**Ejemplos**

```bash
./bin/admin_metrics
./bin/admin_metrics concurrent
./bin/admin_metrics historical
./bin/admin_metrics bytes
./bin/admin_metrics user admin
```

---

## Administración de usuarios en tiempo de ejecución

### Cliente de gestión de usuarios


```bash
./bin/admin_user_mgmt <accion> [args]
```

**Ejemplos**

```bash
./bin/admin_user_mgmt add pepito 1234 user
./bin/admin_user_mgmt role juan admin
./bin/admin_user_mgmt del messi
```

Estos cambios se aplican **sin reiniciar** el servidor SOCKS5.

---

## Pruebas de carga y performance

### Stress de concurrencia

Prueba cantidad máxima de conexiones simultáneas.

```bash
./bin/stress_concurrencies [OPTIONS] <concurrency>
```

**Ejemplo**

```bash
./bin/stress_concurrencies -l 127.0.0.1 -p 1080 -L 127.0.0.1 -P 80 500
```

---

### Stress de throughput

Prueba transferencia sostenida a través del túnel SOCKS5.

**Preparación (eco local)**

```bash
socat TCP-LISTEN:9090,reuseaddr,fork SYSTEM:'cat'
```

```bash
./bin/stress_throughput [OPTIONS] <concurrency> <duration_sec> <payload_bytes>
```

**Ejemplo**

```bash
./bin/stress_throughput -l 127.0.0.1 -p 1080 -L 127.0.0.1 -P 9090 100 10 16384
```

---

## Ejemplo Flujo completo (end-to-end)

```bash
./bin/api
./bin/socks5
./bin/client_ipv4
./bin/admin_metrics
./bin/admin_user_mgmt add pepito 1234 user
```
