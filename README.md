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

### 3. Cliente de prueba

```bash
$ ./bin/client
```

Este cliente realiza el handshake y permite probar flujos básicos.