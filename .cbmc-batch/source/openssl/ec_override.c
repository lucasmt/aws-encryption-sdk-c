/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/ec.h>

#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/nondet.h>

struct ec_group_st {
  bool point_conversion_form_is_set;
};

/*
 * Description: In order to construct a builtin curve use the function EC_GROUP_new_by_curve_name and provide the nid of the curve to be constructed.
 * Return values: All EC_GROUP_new* functions return a pointer to the newly constructed group, or NULL on error.
 */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid) {
  EC_GROUP* ec_group = can_fail_malloc(sizeof(EC_GROUP));
  if (ec_grou) ec_group->point_conversion_form_is_set = false;
  return ec_group;
}

/*
 * Description: The functions EC_GROUP_set_point_conversion_form and EC_GROUP_get_point_conversion_form set and get the point_conversion_form for the curve respectively.
 */
void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form) {
  assert(group);
  group->point_conversion_form_is_set = true;
}

/* 
 * Description: EC_GROUP_free frees the memory associated with the EC_GROUP. If group is NULL nothing is done.
 */
void EC_GROUP_free(EC_GROUP *group) {
  free(group);
}

struct ec_key_st {
  int references;
  bool group_is_set;
  bool point_conversion_form_is_set;
  bool pub_key_is_set;
};

/* Helper function for CBMC proofs: initializes the EC_KEY as nondeterministically as possible. */
void ec_key_nondet_init(EC_KEY* key) {
  int new_reference_count;
  __CPROVER_assume(new_reference_count > 0);
  key->references = new_reference_count;
}

/* Helper function for CBMC proofs: returns the reference count. */
int ec_key_get_reference_count(EC_KEY* key) {
  return key ? key->references : 0;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void ec_key_unconditional_free(EC_KEY* key) {
  free(key);
}

/*
 * Description: A new EC_KEY with no associated curve can be constructed by calling EC_KEY_new(). The reference count for the newly created EC_KEY is initially set to 1.
 * Return value: EC_KEY_new(), EC_KEY_new_by_curve_name() and EC_KEY_dup() return a pointer to the newly created EC_KEY object, or NULL on error.
 */
EC_KEY* EC_KEY_new() {
  EC_KEY* key = can_fail_malloc(sizeof(EC_KEY));

  if (key) {
    key->references = 1;
    key->group_is_set = false; // no associated curve
    key->point_conversion_form_is_set = false;
  }

  return key;
}

/*
 * Description: The function EC_KEY_set_group() sets the EC_GROUP object for the key.
 * Return values: Returns 1 on success or 0 on error.
 */
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group) {
  assert(key);

  if (!group) {
    return 0;
  } else {
    key->group_is_set = nondet_bool(); // can fail for several reasons
    return key->group_is_set;
  }
}

/*
 * Description: The functions EC_KEY_get_conv_form() and EC_KEY_set_conv_form() get and set the point_conversion_form for the key.
 */
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform) {
  assert(eckey);
  // eckey doesn't need to have a group associated with it

  eckey->point_conversion_form_is_set = true;
}

/*
 * Description: Calling EC_KEY_free() decrements the reference count for the EC_KEY object, and if it has dropped to zero then frees the memory associated with it. If key is NULL nothing is done.
 */
void EC_KEY_free(EC_KEY *key) {
  if (key) {
    --(key->references);
    if (key->references == 0) {
      free(key);
    }
  }
}

/** Decodes a ec public key from a octet string.
 *  \param  key  a pointer to a EC_KEY object which should be used
 *  \param  in   memory buffer with the encoded public key
 *  \param  len  length of the encoded public key
 *  \return EC_KEY object with decoded public key or NULL if an error
 *          occurred.
 */
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len) {
  assert(in);
  assert(*in);
  assert(AWS_MEM_IS_READABLE(*in, len));

  if (key == NULL || (*key) == NULL || !(*key)->group_is_set) {
    return NULL;
  }

  // modeling other sources of errors
  if (nondet_bool()) {
    return NULL;
  }

  (*key)->pub_key_is_set = true;

  // in some cases the point conversion form is also set
  if (nondet_bool()) {
    (*key)->point_conversion_form_is_set = nondet_bool();
  }
  *in += len;
  return *key;
}
