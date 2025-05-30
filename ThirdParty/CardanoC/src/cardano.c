/**
 * \file cardano.c
 *
 * \author angel.castillo
 * \date   Mar 13, 2024
 *
 * Copyright 2024 Biglup Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* INCLUDES ******************************************************************/

#include <cardano/cardano.h>

#include "./config.h"
#include <sodium.h>

/* DEFINITIONS ***************************************************************/

const char*
cardano_get_lib_version(void)
{
  return LIB_CARDANO_C_VERSION;
}

void
cardano_memzero(void* const buffer, size_t size)
{
  if ((buffer == NULL) || (size == 0U))
  {
    return;
  }

  sodium_memzero(buffer, size);
}