/*tcs_kernel@tencent.com 20210913*/
#include "gcc-plugin.h"
#include "tree.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "stringpool.h"
#include "attribs.h"
#include "tree-pass.h"
#include "ssa.h"
#include "ssa-iterators.h"
#include "context.h"

#ifndef __visible
#define __visible __attribute__((visibility("default")))
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#define PASS_INFO(NAME, REF, ID, POS)                                          \
  struct register_pass_info NAME##_pass_info = { .pass = make_pass_##NAME(g),  \
                                                 .reference_pass_name = REF,   \
                                                 .ref_pass_instance_number =   \
                                                     ID,                       \
                                                 .pos_op = POS, }

static tree handle_sanitize_struct_attribute(tree *, tree, tree, int, bool *);

/* Handle a "sanitize_struct"  attribute*/
static tree handle_sanitize_struct_attribute(tree *node __unused,
                                             tree name __unused,
                                             tree args __unused,
                                             int flags __unused,
                                             bool *no_add_attrs __unused) {
  return NULL_TREE;
}

gimple_opt_pass *make_pass_struct_san(gcc::context *ctxt);
