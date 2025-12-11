#!/bin/bash

# ==========================================
# Configuración del Servidor SOCKS5
# ==========================================

# Ruta al ejecutable (ajustar si está en otra carpeta, ej: ./bin/server)
EJECUTABLE="./bin/socks5"

# Configuración SOCKS (Proxy)
SOCKS_ADDR="0.0.0.0"   # Escuchar en todas las interfaces
SOCKS_PORT="1080"

# Configuración Management (Admin)
MNG_ADDR="127.0.0.1"   # Escuchar solo localmente (seguridad)
MNG_PORT="8080"

# Usuarios (Formato user:pass)
USER_GUEST="invitado:1234"

# Opciones extra
# -N deshabilita los disectors de contraseñas (quita el # para activar)
# FLAGS_EXTRA="-N" 

# ==========================================
# Ejecución
# ==========================================

# Verificamos si existe el ejecutable
if [ ! -f "$EJECUTABLE" ]; then
    echo "Error: No se encuentra el archivo '$EJECUTABLE'. ¿Ya compilaste?"
    exit 1
fi

echo "--- Iniciando Servidor SOCKS5 ---"
echo "Proxy: $SOCKS_ADDR:$SOCKS_PORT"
echo "Admin: $MNG_ADDR:$MNG_PORT"
echo "Usuarios cargados: 2"
echo "---------------------------------"

# Ejecutar el comando
$EJECUTABLE \
    -l "$SOCKS_ADDR" \
    -p "$SOCKS_PORT" \
    -L "$MNG_ADDR" \
    -P "$MNG_PORT" \
    -u "$USER_GUEST" \
    $FLAGS_EXTRA