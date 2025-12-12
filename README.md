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

## Requisitos previos IMPORTANTES

### 1. Tener la **API corriendo antes de iniciar el servidor SOCKS5**

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
Sin este archivo, la API no podrá levantar correctamente la base de usuarios.

---

## Dependencias

Asegurate de tener instalado:

* **gcc**
* **make**
* **openssl**
  (usado únicamente para funcionalidades auxiliares permitidas por la cátedra y con licencia OSI aprobada)

---

## Compilación

```bash
$ make clean all
```

Esto compila los tres componentes:

* `bin/socks5` → servidor SOCKS5
* `bin/client` → cliente de prueba
* `bin/api` → servidor de administración/monitoreo

---

## Ejecución

### 1. Levantar la API **primero**

```bash
$ ./bin/api
```

### 2. Ejecutar el servidor SOCKS5

```bash
$ ./bin/socks5
```

El servidor queda listo para aceptar múltiples clientes concurrentes y autenticarlos mediante la API.
---

## Clientes de prueba incluidos

El proyecto incluye distintos **clientes de prueba** que permiten validar de forma aislada y end-to-end las funcionalidades requeridas por el enunciado: handshake SOCKS5, autenticación, forwarding, administración en tiempo de ejecución, métricas y concurrencia.

### `./bin/client`

Cliente SOCKS5 básico para **smoke testing end-to-end**.

* Realiza el **handshake SOCKS5 completo** con autenticación usuario/contraseña.
* Credenciales por defecto: `admin / admin`.
* Destino por defecto: `127.0.0.1:1080` (modificable con flags `-l` y `-p`).
* Permite elegir el tipo de destino (**IPv4 / IPv6 / dominio**) modificando en
  `src/client/client.c` la función `perform_request_*`.
* La función `test_tunnel()` envía un **GET HTTP real** a través del proxy para verificar
  el correcto funcionamiento del túnel bidireccional.

Sirve para validar que el proxy funciona de punta a punta.

---

### `./bin/admin_metrics [usuario_para_logs]`

Cliente de **monitoreo y métricas**.

* Conecta al proxy SOCKS5 y realiza un **CONNECT hacia la API** (`::1:ADMIN_PORT`).
* Consulta métricas:

  * conexiones históricas,
  * conexiones concurrentes,
  * bytes transferidos,
  * líneas de log asociadas a un usuario.
* El usuario para filtrar logs puede pasarse por parámetro (por defecto: `admin`).
* Finaliza enviando el comando `QUIT`.

Valida el **pipeline SOCKS5 → API → métricas**, sin bypassar el proxy.

---

### `./bin/admin_user_mgmt`

Cliente de **administración de usuarios en tiempo de ejecución**.

* Conecta al proxy y realiza un **CONNECT hacia la API**.
* Ejecuta comandos de administración de prueba:

  * `ADD_USER`
  * `SET_USER_ROLE`
  * `DELETE_USER`
  * `QUIT`
* Usa datos hardcodeados de demostración (ej: `pepito/1234`, `juan → admin`, `messi`).

Verifica que los **cambios de usuarios se aplican sin reiniciar el servidor**, como exige el enunciado.

---

### `./bin/stress <concurrency> <target_host> <target_port>`

Cliente de **carga y concurrencia**.

* Lanza **N hilos concurrentes**, cada uno realizando:

  * handshake SOCKS5,
  * autenticación (`admin/admin`),
  * `CONNECT` al destino indicado.
* Reporta:

  * conexiones exitosas,
  * fallos,
  * tasa de éxito.

Útil para evaluar **estabilidad, concurrencia y comportamiento bajo carga**.