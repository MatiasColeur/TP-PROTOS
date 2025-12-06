
#!/bin/bash

# Archivo a enviar al cliente
INPUT_FILE="hamlet_sentences.txt"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: no existe $INPUT_FILE"
    exit 1
fi

# Ejecutar un cliente y pasarle Hamlet por stdin
./bin/client < "$INPUT_FILE"
