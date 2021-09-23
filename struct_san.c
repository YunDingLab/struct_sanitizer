/*tcs_kernel@tencent.com 20210913*/
#include "struct_san.h"

int plugin_is_GPL_compatible;

static struct plugin_info rap_plugin_info = { .version = "20210913",
                                              .help = "struct sanitizer" };

static struct attribute_spec sanitize_struct_attr = {
  "sanitize_struct", 0,     0,                                false, false,
  false,             false, handle_sanitize_struct_attribute, NULL
};

static void struct_san_change_section_finish_decl(void *event_data,
                                                  void *data __unused) {
  tree decl = (tree)event_data;

  if (TREE_CODE(decl) != VAR_DECL)
    return;

  if (lookup_attribute("sanitize_struct", TYPE_ATTRIBUTES(TREE_TYPE(decl))))
    set_decl_section_name(decl, ".sanitize_struct");
}

static void register_attributes(void *event_data __unused,
                                void *data __unused) {
  register_attribute(&sanitize_struct_attr);
}

tree get_struct_obj(gimple *stmt) {
  tree rhs, type, t;
  rhs = gimple_assign_rhs1(stmt);
  t = rhs;

  while (TREE_CODE(t) == COMPONENT_REF)
    t = TREE_OPERAND(t, 0);

  if (TREE_CODE(t) == MEM_REF) {
    type = TREE_TYPE(TREE_OPERAND(t, 0));

    while (TREE_CODE(type) == POINTER_TYPE)
      type = TREE_TYPE(type);

    if ((TREE_CODE(type) == RECORD_TYPE) &&
        lookup_attribute("sanitize_struct", TYPE_ATTRIBUTES(type)))
      return build1(ADDR_EXPR, const_ptr_type_node, rhs);
  }

  return NULL_TREE;
}

int ssan_instrument() {
  basic_block bb = NULL;
  gimple *stmt, *def_stmt, *use_stmt, *call_stmt;
  tree call_fn, lhs, tmp_var;
  imm_use_iterator iterator;

  tree func_type = build_function_type_list(
      const_ptr_type_node, const_ptr_type_node, const_ptr_type_node, NULL_TREE);
  tree fndecl = build_fn_decl("__sanitizer_struct_guard__", func_type);

  FOR_EACH_BB_FN(bb, cfun) {
    gimple_stmt_iterator gsi;
    for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
      stmt = gsi_stmt(gsi);

      if (!is_gimple_call(stmt))
        continue;

      call_fn = gimple_call_fn(stmt);
      if (!call_fn || TREE_CODE(call_fn) != SSA_NAME || SSA_NAME_VAR(call_fn))
        continue;

      def_stmt = SSA_NAME_DEF_STMT(call_fn);
      if (!is_gimple_assign(def_stmt))
        continue;

      tmp_var = get_struct_obj(def_stmt);
      if (tmp_var == NULL_TREE)
        continue;

      lhs = gimple_assign_lhs(def_stmt);
      call_stmt = gimple_build_call(fndecl, 2, tmp_var, lhs);
      tmp_var = make_temp_ssa_name(TREE_TYPE(lhs), NULL, "STRUCT_I");
      gimple_call_set_lhs(call_stmt, tmp_var);
      update_stmt(call_stmt);

      FOR_EACH_IMM_USE_STMT(use_stmt, iterator, lhs) {
        use_operand_p use_p;

        if (use_stmt == call_stmt)
          continue;

        FOR_EACH_IMM_USE_ON_STMT(use_p, iterator)
        SET_USE(use_p, tmp_var);

        update_stmt(use_stmt);
      }
      gsi_insert_before(&gsi, call_stmt, GSI_NEW_STMT);
    }
  }
  return 0;
}

namespace {
const pass_data pass_data_struct_san = {
  GIMPLE_PASS,                                /*type*/
  "ssan",                                     /*name*/
  OPTGROUP_NONE,                              /*optinfo_flags*/
  TV_NONE,                                    /*tv_id*/
  (PROP_ssa | PROP_cfg | PROP_gimple_leh), 0, /*properties_provided*/
  0,                                          /*properties_destroyed*/
  0,                                          /*todo_flags_start*/
  TODO_update_ssa,                            /*todo_flags_finish*/
};

class pass_struct_san : public gimple_opt_pass {
public:
  pass_struct_san(gcc::context *ctxt)
      : gimple_opt_pass(pass_data_struct_san, ctxt) {}
  opt_pass *clone() { return new pass_struct_san(m_ctxt); }
  virtual bool gate(function *) {
    return lookup_attribute("sanitize_struct",
                            DECL_ATTRIBUTES(current_function_decl));
  }
  virtual unsigned int execute(function *) {
    return ssan_instrument();
  };
};
}

gimple_opt_pass *make_pass_struct_san(gcc::context *ctxt) {
  return new pass_struct_san(ctxt);
}

__visible int plugin_init(struct plugin_name_args *plugin_info,
                          struct plugin_gcc_version *version) {
  const char *const plugin_name = plugin_info->base_name;
  PASS_INFO(struct_san, "asan", 0, PASS_POS_INSERT_BEFORE);

  register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
  register_callback(plugin_name, PLUGIN_FINISH_DECL,
                    struct_san_change_section_finish_decl, NULL);
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                    &struct_san_pass_info);
  return 0;
}
