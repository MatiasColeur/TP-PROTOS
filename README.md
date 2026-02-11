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
Sin este archivo, la API no podrá levantar correctamente la base de usuarios. La API mapea `users.csv`, verifica su `mtime` antes de ejecutar comandos de administración y recarga automáticamente cualquier modificación que se haga sobre el archivo en el sistema de archivos.

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

Todos los binarios soportan `-h` para ver opciones completas y valores por defecto.

---

### 1) Admin API

> **Debe ejecutarse antes del servidor SOCKS5**

**Genérico**

```bash
./bin/api [OPTIONS]
```

**Opciones principales**

* `-l <addr>` Dirección donde escucha la API (default: `::1`)
* `-p <port>` Puerto de la API (default: `8080`)

**Ejemplos**

```bash
./bin/api
./bin/api -l ::1 -p 8080
./bin/api -l :: -p 8080
```

---

### 2) Servidor SOCKS5

**Genérico**

```bash
./bin/socks5 [OPTIONS]
```

**Opciones principales**

* `-l <SOCKS addr>` Dirección donde escucha el proxy
* `-p <SOCKS port>` Puerto del proxy
* `-L <MNG addr>` Dirección de la API de management
* `-P <MNG port>` Puerto de la API
  * `-P` también controla el puerto al que el servidor intenta llegar mediante CONNECT cuando coloca un túnel hacia la API a través del proxy (y lo respeta tanto `bootstrap` como las rutinas de gestión).
* `-u <user:pass>` Usuarios iniciales
* `-N` Deshabilita dissectors
* `-v` Versión

**Ejemplos**

```bash
./bin/socks5
./bin/socks5 -L ::1 -P 8080
./bin/socks5 -l ::1 -p 1080 -L ::1 -P 8080 -u maxi:chiate
```

---

## Clientes SOCKS5 (smoke tests)

Clientes simples para validar handshake, auth y CONNECT.

---

### Cliente IPv4

**Genérico**

```bash
./bin/client_ipv4 [OPTIONS]
```

**Opciones**

* `-l <SOCKS addr>` (default: `127.0.0.1`)
* `-p <SOCKS port>` (default: `1080`)
* `-L <dst IPv4>` (default: `142.250.190.14`)
* `-P <dst port>` (default: `80`)

**Ejemplo**

```bash
./bin/client_ipv4
./bin/client_ipv4 -L 142.250.190.14 -P 80
```

---

### Cliente IPv6

**Genérico**

```bash
./bin/client_ipv6 [OPTIONS]
```

**Opciones**

* `-l <SOCKS addr>`
* `-p <SOCKS port>`
* `-L <dst IPv6>` (default: `2606:4700:4700::1111`)
* `-P <dst port>`

**Ejemplo**

```bash
./bin/client_ipv6
./bin/client_ipv6 -L 2606:4700:4700::1111 -P 80
```

---

### Cliente DNS (FQDN)

**Genérico**

```bash
./bin/client_dns [OPTIONS]
```

**Opciones**

* `-l <SOCKS addr>`
* `-p <SOCKS port>`
* `-L <dest host>` (default: `google.com`)
* `-P <dest port>` (default: `80`)

**Ejemplo**

```bash
./bin/client_dns
./bin/client_dns -L google.com -P 80
```

---

## Métricas y monitoreo

### Cliente de métricas (vía SOCKS → API)

**Genérico**

```bash
./bin/admin_metrics [OPTIONS]
```

**Opciones**

* `-H` Conexiones históricas
* `-C` Conexiones concurrentes
* `-B` Bytes transferidos
* `-U <user>` Logs/conexiones de un usuario
* `-l <addr>` Host donde escucha el proxy SOCKS (por defecto `127.0.0.1`)
* `-p <port>` Puerto donde escucha el proxy SOCKS (por defecto `1080`)
* `-A <addr>` Host donde escucha la API de administración (por defecto `::1`)
* `-P <port>` Puerto donde escucha la API (por defecto `8080`). Úsalo si la API se ejecuta en otro puerto, por ejemplo `./bin/admin_metrics -P 8081`.

**Ejemplos**

```bash
./bin/admin_metrics -H
./bin/admin_metrics -C -B
./bin/admin_metrics -U admin
```

---

## Administración de usuarios en tiempo de ejecución

### Cliente de gestión de usuarios

**Genérico**

```bash
./bin/admin_user_mgmt [OPTIONS] ACTION
```

**Acciones**

* `-A <user> <role>` Agregar usuario (se solicita la contraseña sin eco)
* `-R <user> <role>` Cambiar rol
* `-D <user>` Eliminar usuario

**Opciones**

* `-l <addr>` Host donde escucha el proxy SOCKS (por defecto `127.0.0.1`)
* `-p <port>` Puerto donde escucha el proxy SOCKS (por defecto `1080`)
* `-a <addr>` Host donde escucha la API de administración (por defecto `::1`)
* `-P <port>` Puerto donde escucha la API (por defecto `8080`)

**Ejemplos**

```bash
./bin/admin_user_mgmt -A pepito user
./bin/admin_user_mgmt -R juan admin
./bin/admin_user_mgmt -D messi
./bin/admin_user_mgmt -l 192.168.0.10 -p 1080 -a 192.168.0.20 -P 8080 -A pepito user
```

Al ejecutar `-A` se pedirá la contraseña de forma interactiva y no se imprimirá en pantalla (ni quedará en el historial de la shell).

Los cambios se aplican **sin reiniciar** el servidor SOCKS5.

---

## Pruebas de carga y performance

### Stress de concurrencia

Evalúa la cantidad máxima de conexiones simultáneas.

**Genérico**

```bash
./bin/stress_concurrencies [OPTIONS] <concurrency>
```

**Ejemplo**

```bash
./bin/stress_concurrencies 500
./bin/stress_concurrencies -L 127.0.0.1 -P 80 500
```

---

### Stress de throughput

Evalúa transferencia sostenida de datos a través del túnel SOCKS5.

**Preparación (eco local)**

```bash
socat TCP-LISTEN:9090,reuseaddr,fork SYSTEM:'cat'
```

**Genérico**

```bash
./bin/stress_throughput [OPTIONS] <concurrency> <duration_sec> [payload_bytes]
```

**Ejemplo**

```bash
./bin/stress_throughput 100 10
./bin/stress_throughput -L 127.0.0.1 -P 9090 100 10 16384
```

---

## Ejemplo de flujo completo (end-to-end)

```bash
./bin/api
./bin/socks5
./bin/client_ipv4
./bin/admin_metrics -H -C
./bin/admin_user_mgmt -A pepito 1234 user
```

## Protocolo de conexion entre API y SERVER

### 1. Diseño del Protocolo (El "Contrato")

**Estructura del Paquete:**

| Byte 0 | Byte 1 | Byte 2-3 | Byte 4 ... N |
| --- | --- | --- | --- |
| **Versión** | **CMD (Opcode)** | **Payload Length** | **Payload Data** |

* **Ver:** Versión del protocolo (ej: 1).
* **CMD:** Qué queremos hacer (ej: 0x01 = Get Metrics, 0x02 = Add User).
* **Len:** Cuántos bytes de datos vienen después (uint16 big-endian).
* **Payload:** Los argumentos o la respuesta.
