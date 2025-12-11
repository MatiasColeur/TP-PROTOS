#ifndef __BOOTSTRAP_H__
#define __BOOTSTRAP_H__

#include "errors.h"
#include "shared.h"
#include "api.h"
#include "parser_arguments.h"
#include "socks5.h"

void bootstrap_cli_users_via_api(const ProgramArgs *args);

#endif // __BOOTSTRAP_H__
