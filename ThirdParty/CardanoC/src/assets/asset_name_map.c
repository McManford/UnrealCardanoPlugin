/**
 * \file asset_name_map.c
 *
 * \author angel.castillo
 * \date   May 12, 2024
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

#include <cardano/assets/asset_name.h>
#include <cardano/assets/asset_name_list.h>
#include <cardano/assets/asset_name_map.h>
#include <cardano/object.h>

#include "../allocators.h"
#include "../cbor/cbor_validation.h"
#include "../collections/array.h"

#include <assert.h>
#include <string.h>

/* STRUCTURES ****************************************************************/

/**
 * \brief Represents a map of asset name to coin amount.
 */
typedef struct cardano_asset_name_map_t
{
    cardano_object_t base;
    cardano_array_t* array;
} cardano_asset_name_map_t;

/**
 * \brief Represents a Cardano asset name map key value pair.
 */
typedef struct cardano_asset_name_map_kvp_t
{
    cardano_object_t      base;
    cardano_asset_name_t* key;
    int64_t               value;
} cardano_asset_name_map_kvp_t;

/* STATIC FUNCTIONS **********************************************************/

/**
 * \brief Deallocates a asset_name map object.
 *
 * This function is responsible for properly deallocating a asset_name map object (`cardano_asset_name_map_t`)
 * and its associated resources.
 *
 * \param object A void pointer to the asset_name_map object to be deallocated. The function casts this
 *               pointer to the appropriate type (`cardano_asset_name_map_t*`).
 *
 * \note It is assumed that this function is called only when the reference count of the asset_name_map
 *       object reaches zero, as part of the reference counting mechanism implemented for managing the
 *       lifecycle of these objects.
 */
static void
cardano_asset_name_map_deallocate(void* object)
{
  assert(object != NULL);

  cardano_asset_name_map_t* map = (cardano_asset_name_map_t*)object;

  if (map->array != NULL)
  {
    cardano_array_unref(&map->array);
  }

  _cardano_free(map);
}

/**
 * \brief Deallocates a asset_name map key value pair object.
 *
 * This function is responsible for properly deallocating a asset_name map key value pair object (`cardano_asset_name_map_kvp_t`)
 * and its associated resources.
 *
 * \param object A void pointer to the asset_name_map object to be deallocated. The function casts this
 *               pointer to the appropriate type (`cardano_asset_name_map_kvp_t*`).
 *
 * \note It is assumed that this function is called only when the reference count of the asset_name_map
 *       object reaches zero, as part of the reference counting mechanism implemented for managing the
 *       lifecycle of these objects.
 */
static void
cardano_asset_name_map_kvp_deallocate(void* object)
{
  assert(object != NULL);

  cardano_asset_name_map_kvp_t* map = (cardano_asset_name_map_kvp_t*)object;

  cardano_asset_name_unref(&map->key);

  _cardano_free(map);
}

/**
 * \brief Compares two cardano_object_t objects based on their asset_name.
 *
 * @param lhs Pointer to the first cardano_object_t object.
 * @param rhs Pointer to the second cardano_object_t object.
 *
 * @return true if the addresses are equal, false otherwise.
 */
static bool
asset_name_equals(const cardano_asset_name_t* lhs, const cardano_asset_name_t* rhs)
{
  if (lhs == NULL)
  {
    return false;
  }

  if (rhs == NULL)
  {
    return false;
  }

  const size_t lhs_size = cardano_asset_name_get_bytes_size(lhs);
  const size_t rhs_size = cardano_asset_name_get_bytes_size(rhs);

  if (lhs_size != rhs_size)
  {
    return false;
  }

  const uint8_t* lhs_bytes = cardano_asset_name_get_bytes(lhs);
  const uint8_t* rhs_bytes = cardano_asset_name_get_bytes(rhs);

  return memcmp(lhs_bytes, rhs_bytes, lhs_size) == 0;
}

/**
 * \brief Compares two cardano_asset_name_map_kvp_t objects based on their asset_name.
 *
 * \param[in] lhs Pointer to the first cardano_object_t object.
 * \param[in] rhs Pointer to the second cardano_object_t object.
 * \param[in] context A pointer to the context object.
 *
 * \return A negative value if the address of lhs is less than the address of rhs, zero if they are equal,
 *         and a positive value if the address of lhs is greater than the address of rhs.
 */
static int32_t
compare_by_bytes(const cardano_object_t* lhs, const cardano_object_t* rhs, void* context)
{
  assert(lhs != NULL);
  assert(rhs != NULL);

  CARDANO_UNUSED(context);

  const cardano_asset_name_map_kvp_t* lhs_kvp = (const cardano_asset_name_map_kvp_t*)((const void*)lhs);
  const cardano_asset_name_map_kvp_t* rhs_kvp = (const cardano_asset_name_map_kvp_t*)((const void*)rhs);

  const size_t lhs_size = cardano_asset_name_get_bytes_size(lhs_kvp->key);
  const size_t rhs_size = cardano_asset_name_get_bytes_size(rhs_kvp->key);

  if (lhs_size != rhs_size)
  {
    return (lhs_size < rhs_size) ? -1 : 1;
  }

  const uint8_t* lhs_bytes = cardano_asset_name_get_bytes(lhs_kvp->key);
  const uint8_t* rhs_bytes = cardano_asset_name_get_bytes(rhs_kvp->key);

  return memcmp(lhs_bytes, rhs_bytes, lhs_size);
}

/**
 * \brief Predicate function that returns true if the value of the cardano_asset_name_map_kvp_t object is different than zero.
 *
 * @param element Pointer to the cardano_object_t object.
 * @return true if the value of the cardano_asset_name_map_kvp_t object is different than zero, false otherwise.
 */
static bool
different_than_zero(const cardano_object_t* element, const void* context)
{
  CARDANO_UNUSED(context);

  const cardano_asset_name_map_kvp_t* kvp = (const cardano_asset_name_map_kvp_t*)((const void*)element);

  if (kvp == NULL)
  {
    return false;
  }

  return kvp->value != 0;
}

/* DEFINITIONS ****************************************************************/

cardano_error_t
cardano_asset_name_map_new(cardano_asset_name_map_t** asset_name_map)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_asset_name_map_t* map = _cardano_malloc(sizeof(cardano_asset_name_map_t));

  if (map == NULL)
  {
    return CARDANO_ERROR_MEMORY_ALLOCATION_FAILED;
  }

  map->base.ref_count     = 1;
  map->base.last_error[0] = '\0';
  map->base.deallocator   = cardano_asset_name_map_deallocate;

  map->array = cardano_array_new(32);

  if (map->array == NULL)
  {
    _cardano_free(map);
    return CARDANO_ERROR_MEMORY_ALLOCATION_FAILED;
  }

  *asset_name_map = map;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_from_cbor(cardano_cbor_reader_t* reader, cardano_asset_name_map_t** asset_name_map)
{
  if (reader == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_asset_name_map_t* map    = NULL;
  cardano_error_t           result = cardano_asset_name_map_new(&map);

  if (result != CARDANO_SUCCESS)
  {
    return result;
  }

  int64_t length = 0;

  result = cardano_cbor_reader_read_start_map(reader, &length);

  if (result != CARDANO_SUCCESS)
  {
    cardano_asset_name_map_unref(&map);
    return result;
  }

  cardano_cbor_reader_state_t state = CARDANO_CBOR_READER_STATE_UNDEFINED;

  while (state != CARDANO_CBOR_READER_STATE_END_MAP)
  {
    result = cardano_cbor_reader_peek_state(reader, &state);

    if (result != CARDANO_SUCCESS)
    {
      cardano_asset_name_map_unref(&map);
      return result;
    }

    if (state == CARDANO_CBOR_READER_STATE_END_MAP)
    {
      break;
    }

    cardano_asset_name_t* key   = NULL;
    int64_t               value = 0;

    cardano_error_t asset_name_result = cardano_asset_name_from_cbor(reader, &key);

    if (asset_name_result != CARDANO_SUCCESS)
    {
      cardano_asset_name_map_unref(&map);
      return asset_name_result;
    }

    result = cardano_cbor_reader_read_int(reader, &value);

    if (result != CARDANO_SUCCESS)
    {
      cardano_asset_name_unref(&key);
      cardano_asset_name_map_unref(&map);
      return result;
    }

    cardano_asset_name_map_kvp_t* kvp = _cardano_malloc(sizeof(cardano_asset_name_map_kvp_t));

    if (kvp == NULL)
    {
      cardano_asset_name_unref(&key);
      cardano_asset_name_map_unref(&map);

      return CARDANO_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    kvp->base.ref_count     = 0;
    kvp->base.last_error[0] = '\0';
    kvp->base.deallocator   = cardano_asset_name_map_kvp_deallocate;
    kvp->key                = key;
    kvp->value              = value;

    const size_t old_size = cardano_array_get_size(map->array);
    const size_t new_size = cardano_array_push(map->array, (cardano_object_t*)((void*)kvp));

    assert((old_size + 1U) == new_size);

    CARDANO_UNUSED(old_size);
    CARDANO_UNUSED(new_size);
  }

  cardano_array_sort(map->array, compare_by_bytes, NULL);

  result = cardano_cbor_validate_end_map("asset_name_map", reader);

  if (result != CARDANO_SUCCESS)
  {
    cardano_asset_name_map_unref(&map);
    return result;
  }

  *asset_name_map = map;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_to_cbor(const cardano_asset_name_map_t* asset_name_map, cardano_cbor_writer_t* writer)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (writer == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_error_t result = CARDANO_SUCCESS;

  size_t map_size = cardano_array_get_size(asset_name_map->array);
  result          = cardano_cbor_writer_write_start_map(writer, (int64_t)map_size);

  if (result != CARDANO_SUCCESS)
  {
    return result;
  }

  for (size_t i = 0; i < cardano_array_get_size(asset_name_map->array); ++i)
  {
    cardano_object_t* kvp = cardano_array_get(asset_name_map->array, i);
    cardano_object_unref(&kvp);

    if (kvp == NULL)
    {
      cardano_cbor_writer_set_last_error(writer, "Element in asset_name map is NULL");
      return CARDANO_ERROR_ENCODING;
    }

    cardano_asset_name_map_kvp_t* kvp_data = (cardano_asset_name_map_kvp_t*)((void*)kvp);

    cardano_error_t write_asset_name_result = cardano_cbor_writer_write_bytestring(writer, cardano_asset_name_get_bytes(kvp_data->key), cardano_asset_name_get_bytes_size(kvp_data->key));

    if (write_asset_name_result != CARDANO_SUCCESS)
    {
      return result;
    }

    result = cardano_cbor_writer_write_signed_int(writer, kvp_data->value);

    if (result != CARDANO_SUCCESS)
    {
      return result;
    }
  }

  return CARDANO_SUCCESS;
}

size_t
cardano_asset_name_map_get_length(const cardano_asset_name_map_t* asset_name_map)
{
  if (asset_name_map == NULL)
  {
    return 0;
  }

  return cardano_array_get_size(asset_name_map->array);
}

cardano_error_t
cardano_asset_name_map_get(cardano_asset_name_map_t* asset_name_map, cardano_asset_name_t* key, int64_t* element)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (key == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (element == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  for (size_t i = 0; i < cardano_array_get_size(asset_name_map->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(asset_name_map->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

    if (asset_name_equals(kvp->key, key))
    {
      *element = kvp->value;

      cardano_object_unref(&object);
      return CARDANO_SUCCESS;
    }

    cardano_object_unref(&object);
  }

  return CARDANO_ERROR_ELEMENT_NOT_FOUND;
}

cardano_error_t
cardano_asset_name_map_insert(
  cardano_asset_name_map_t* asset_name_map,
  cardano_asset_name_t*     key,
  const int64_t             value)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (key == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  for (size_t i = 0; i < cardano_array_get_size(asset_name_map->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(asset_name_map->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

    cardano_object_unref(&object);

    if (asset_name_equals(kvp->key, key))
    {
      kvp->value = value;

      return CARDANO_SUCCESS;
    }
  }

  cardano_asset_name_map_kvp_t* kvp = _cardano_malloc(sizeof(cardano_asset_name_map_kvp_t));

  if (kvp == NULL)
  {
    return CARDANO_ERROR_MEMORY_ALLOCATION_FAILED;
  }

  kvp->base.ref_count     = 0;
  kvp->base.last_error[0] = '\0';
  kvp->base.deallocator   = cardano_asset_name_map_kvp_deallocate;
  kvp->key                = key;
  kvp->value              = value;

  cardano_asset_name_ref(key);

  const size_t old_size = cardano_array_get_size(asset_name_map->array);
  const size_t new_size = cardano_array_push(asset_name_map->array, (cardano_object_t*)((void*)kvp));

  assert((old_size + 1U) == new_size);

  CARDANO_UNUSED(old_size);
  CARDANO_UNUSED(new_size);

  cardano_array_sort(asset_name_map->array, compare_by_bytes, NULL);

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_get_keys(
  cardano_asset_name_map_t*   asset_name_map,
  cardano_asset_name_list_t** keys)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (keys == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_asset_name_list_t* list = NULL;

  cardano_error_t result = cardano_asset_name_list_new(&list);

  if (result != CARDANO_SUCCESS)
  {
    return result;
  }

  for (size_t i = 0; i < cardano_array_get_size(asset_name_map->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(asset_name_map->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

    result = cardano_asset_name_list_add(list, kvp->key);

    if (result != CARDANO_SUCCESS)
    {
      cardano_asset_name_list_unref(&list);
      cardano_object_unref(&object);
      return result;
    }

    cardano_object_unref(&object);
  }

  *keys = list;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_get_key_at(
  const cardano_asset_name_map_t* asset_name_map,
  const size_t                    index,
  cardano_asset_name_t**          asset_name)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (asset_name == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (index >= cardano_array_get_size(asset_name_map->array))
  {
    return CARDANO_ERROR_INDEX_OUT_OF_BOUNDS;
  }

  cardano_object_t*             object = cardano_array_get(asset_name_map->array, index);
  cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

  cardano_asset_name_ref(kvp->key);
  cardano_object_unref(&object);

  *asset_name = kvp->key;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_get_value_at(
  const cardano_asset_name_map_t* asset_name_map,
  const size_t                    index,
  int64_t*                        amount)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (amount == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (index >= cardano_array_get_size(asset_name_map->array))
  {
    return CARDANO_ERROR_INDEX_OUT_OF_BOUNDS;
  }

  cardano_object_t*             object = cardano_array_get(asset_name_map->array, index);
  cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

  cardano_object_unref(&object);

  *amount = kvp->value;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_get_key_value_at(
  const cardano_asset_name_map_t* asset_name_map,
  const size_t                    index,
  cardano_asset_name_t**          asset_name,
  int64_t*                        amount)
{
  if (asset_name_map == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (asset_name == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (amount == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (index >= cardano_array_get_size(asset_name_map->array))
  {
    return CARDANO_ERROR_INDEX_OUT_OF_BOUNDS;
  }

  cardano_object_t*             object = cardano_array_get(asset_name_map->array, index);
  cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);

  cardano_asset_name_ref(kvp->key);
  cardano_object_unref(&object);

  *asset_name = kvp->key;
  *amount     = kvp->value;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_add(
  const cardano_asset_name_map_t* lhs,
  const cardano_asset_name_map_t* rhs,
  cardano_asset_name_map_t**      result)
{
  if (lhs == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (rhs == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (result == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_asset_name_map_t* map = NULL;

  cardano_error_t create_result = cardano_asset_name_map_new(&map);

  if (create_result != CARDANO_SUCCESS)
  {
    return create_result;
  }

  for (size_t i = 0; i < cardano_array_get_size(lhs->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(lhs->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);
    cardano_object_unref(&object);

    cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, kvp->value);

    if (insert_result != CARDANO_SUCCESS)
    {
      cardano_asset_name_map_unref(&map);
      return insert_result;
    }
  }

  for (size_t i = 0; i < cardano_array_get_size(rhs->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(rhs->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);
    cardano_object_unref(&object);

    int64_t value = 0;

    cardano_error_t get_result = cardano_asset_name_map_get(map, kvp->key, &value);

    if (get_result == CARDANO_SUCCESS)
    {
      value += kvp->value;

      cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, value);

      if (insert_result != CARDANO_SUCCESS)
      {
        cardano_asset_name_map_unref(&map);
        return insert_result;
      }
    }
    else
    {
      cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, kvp->value);

      if (insert_result != CARDANO_SUCCESS)
      {
        cardano_asset_name_map_unref(&map);
        return insert_result;
      }
    }
  }

  cardano_array_t* filtered = cardano_array_filter(map->array, different_than_zero, NULL);

  cardano_array_unref(&map->array);
  map->array = filtered;

  *result = map;

  return CARDANO_SUCCESS;
}

cardano_error_t
cardano_asset_name_map_subtract(
  const cardano_asset_name_map_t* lhs,
  const cardano_asset_name_map_t* rhs,
  cardano_asset_name_map_t**      result)
{
  if (lhs == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (rhs == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  if (result == NULL)
  {
    return CARDANO_ERROR_POINTER_IS_NULL;
  }

  cardano_asset_name_map_t* map = NULL;

  cardano_error_t create_result = cardano_asset_name_map_new(&map);

  if (create_result != CARDANO_SUCCESS)
  {
    return create_result;
  }

  for (size_t i = 0; i < cardano_array_get_size(lhs->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(lhs->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);
    cardano_object_unref(&object);

    cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, kvp->value);

    if (insert_result != CARDANO_SUCCESS)
    {
      cardano_asset_name_map_unref(&map);
      return insert_result;
    }
  }

  for (size_t i = 0; i < cardano_array_get_size(rhs->array); ++i)
  {
    cardano_object_t*             object = cardano_array_get(rhs->array, i);
    cardano_asset_name_map_kvp_t* kvp    = (cardano_asset_name_map_kvp_t*)((void*)object);
    cardano_object_unref(&object);

    int64_t value = 0;

    cardano_error_t get_result = cardano_asset_name_map_get(map, kvp->key, &value);

    if (get_result == CARDANO_SUCCESS)
    {
      value -= kvp->value;

      cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, value);

      if (insert_result != CARDANO_SUCCESS)
      {
        cardano_asset_name_map_unref(&map);
        return insert_result;
      }
    }
    else
    {
      cardano_error_t insert_result = cardano_asset_name_map_insert(map, kvp->key, -kvp->value);

      if (insert_result != CARDANO_SUCCESS)
      {
        cardano_asset_name_map_unref(&map);
        return insert_result;
      }
    }
  }

  cardano_array_t* filtered = cardano_array_filter(map->array, different_than_zero, NULL);

  cardano_array_unref(&map->array);
  map->array = filtered;

  *result = map;

  return CARDANO_SUCCESS;
}

bool
cardano_asset_name_map_equals(const cardano_asset_name_map_t* lhs, const cardano_asset_name_map_t* rhs)
{
  if (lhs == rhs)
  {
    return true;
  }

  if (lhs == NULL)
  {
    return false;
  }

  if (rhs == NULL)
  {
    return false;
  }

  if (cardano_array_get_size(lhs->array) != cardano_array_get_size(rhs->array))
  {
    return false;
  }

  for (size_t i = 0; i < cardano_array_get_size(lhs->array); ++i)
  {
    cardano_object_t*             lhs_object = cardano_array_get(lhs->array, i);
    cardano_asset_name_map_kvp_t* lhs_kvp    = (cardano_asset_name_map_kvp_t*)((void*)lhs_object);
    cardano_object_unref(&lhs_object);

    if (lhs_kvp == NULL)
    {
      return false;
    }

    cardano_object_t*             rhs_object = cardano_array_get(rhs->array, i);
    cardano_asset_name_map_kvp_t* rhs_kvp    = (cardano_asset_name_map_kvp_t*)((void*)rhs_object);
    cardano_object_unref(&rhs_object);

    if (rhs_kvp == NULL)
    {
      return false;
    }

    if (!asset_name_equals(lhs_kvp->key, rhs_kvp->key))
    {
      return false;
    }

    if (lhs_kvp->value != rhs_kvp->value)
    {
      return false;
    }
  }

  return true;
}

void
cardano_asset_name_map_unref(cardano_asset_name_map_t** asset_name_map)
{
  if ((asset_name_map == NULL) || (*asset_name_map == NULL))
  {
    return;
  }

  cardano_object_t* object = &(*asset_name_map)->base;
  cardano_object_unref(&object);

  if (object == NULL)
  {
    *asset_name_map = NULL;
    return;
  }
}

void
cardano_asset_name_map_ref(cardano_asset_name_map_t* asset_name_map)
{
  if (asset_name_map == NULL)
  {
    return;
  }

  cardano_object_ref(&asset_name_map->base);
}

size_t
cardano_asset_name_map_refcount(const cardano_asset_name_map_t* asset_name_map)
{
  if (asset_name_map == NULL)
  {
    return 0;
  }

  return cardano_object_refcount(&asset_name_map->base);
}

void
cardano_asset_name_map_set_last_error(cardano_asset_name_map_t* asset_name_map, const char* message)
{
  cardano_object_set_last_error(&asset_name_map->base, message);
}

const char*
cardano_asset_name_map_get_last_error(const cardano_asset_name_map_t* asset_name_map)
{
  return cardano_object_get_last_error(&asset_name_map->base);
}
