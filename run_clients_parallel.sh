
#!/bin/bash

# Cantidad de clientes a ejecutar
N="$1"

if [ -z "$N" ]; then
    echo "Uso: $0 <cantidad_de_clientes>"
    exit 1
fi

for ((i=1; i<=N; i++)); do
    ./run_client.sh &
done

wait
echo "Listo, terminaron los $N clientes."
