#ifndef API_SERVICE_H
#define API_SERVICE_H

#include "selector.h"

/**
 * Handler para aceptar conexiones entrantes en el puerto de administración.
 * Registra este handler en el selector con el socket servidor (listener).
 */
extern const struct fd_handler api_passive_handler;

#endif