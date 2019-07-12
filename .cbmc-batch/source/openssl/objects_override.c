#include <openssl/objects.h>

#include <proof_helpers/nondet.h>

/*
 * Description: OBJ_txt2nid() returns NID corresponding to text string <s>. s can be a long name, a short name or the numerical representation of an object.
 * Return values: OBJ_txt2nid() returns a NID or NID_undef on error.
 */
int OBJ_txt2nid(const char *s) {
  return nondet_bool() ? nondet_int() : NID_undef;
}
