// SPDX-License-Identifier: GPL-2.0-only
/*
 * Emit references to functions which may return a Linux errno. In addition to
 * constants and simple SSA values, use Ranger-proven ranges and recognize the
 * common IS_ERR()/PTR_ERR() control-flow pattern.
 */

#include "gcc-common.h"

#if BUILDING_GCC_VERSION >= 11000
/* gcc-common.h uses compatibility macros for the pre-GCC-6 GIMPLE API. */
#undef gimple
#undef const_gimple
#include "gimple-range.h"
#define gimple gimple_ptr
#define const_gimple const_gimple_ptr
#endif

__visible int plugin_is_GPL_compatible;

static bool disable;

#define MAX_ERRNO 4095
#define MAX_VALUE_DEPTH 64

static struct plugin_info fmodret_candidates_plugin_info = {
	.version = PLUGIN_VERSION,
	.help = "disable\tdo not emit fmod_ret candidates\n",
};

static bool is_signed_int_or_long(tree type)
{
	type = TYPE_MAIN_VARIANT(type);

	return type == integer_type_node || type == long_integer_type_node;
}

static bool is_errno_constant(tree value)
{
	HOST_WIDE_INT error;

	if (TREE_CODE(value) != INTEGER_CST || !tree_fits_shwi_p(value))
		return false;

	error = tree_to_shwi(value);
	return error >= -MAX_ERRNO && error < 0;
}

static tree converted_pointer(tree value)
{
	unsigned int depth;

	for (depth = 0; value && depth < MAX_VALUE_DEPTH; depth++) {
		gimple def;

		if (TREE_CODE(value) != SSA_NAME)
			return NULL_TREE;
		if (POINTER_TYPE_P(TREE_TYPE(value)))
			return value;
		def = SSA_NAME_DEF_STMT(value);
		if (!def || !is_gimple_assign(def) ||
		    (!gimple_assign_copy_p(def) && !gimple_assign_cast_p(def)))
			return NULL_TREE;
		value = gimple_assign_rhs1(def);
	}
	return NULL_TREE;
}

static enum tree_code swap_comparison(enum tree_code code)
{
	switch (code) {
	case LT_EXPR:
		return GT_EXPR;
	case LE_EXPR:
		return GE_EXPR;
	case GT_EXPR:
		return LT_EXPR;
	case GE_EXPR:
		return LE_EXPR;
	default:
		return code;
	}
}

static enum tree_code invert_comparison(enum tree_code code)
{
	switch (code) {
	case LT_EXPR:
		return GE_EXPR;
	case LE_EXPR:
		return GT_EXPR;
	case GT_EXPR:
		return LE_EXPR;
	case GE_EXPR:
		return LT_EXPR;
	case EQ_EXPR:
		return NE_EXPR;
	case NE_EXPR:
		return EQ_EXPR;
	default:
		return ERROR_MARK;
	}
}

static bool unsigned_pointer_value(tree value, tree pointer)
{
	gimple def;
	tree rhs;

	if (TREE_CODE(value) != SSA_NAME || !INTEGRAL_TYPE_P(TREE_TYPE(value)) ||
	    !TYPE_UNSIGNED(TREE_TYPE(value)))
		return false;
	def = SSA_NAME_DEF_STMT(value);
	if (!def || !is_gimple_assign(def) || !gimple_assign_cast_p(def))
		return false;
	rhs = gimple_assign_rhs1(def);
	return POINTER_TYPE_P(TREE_TYPE(rhs)) && rhs == pointer;
}

static bool condition_implies_is_err(gimple stmt, bool truth, tree pointer)
{
	enum tree_code code;
	wide_int limit;
	wide_int threshold;
	tree integer;
	tree constant;
	tree type;

	if (gimple_code(stmt) != GIMPLE_COND)
		return false;
	code = gimple_cond_code(stmt);
	integer = gimple_cond_lhs(stmt);
	constant = gimple_cond_rhs(stmt);
	if (!unsigned_pointer_value(integer, pointer)) {
		integer = gimple_cond_rhs(stmt);
		constant = gimple_cond_lhs(stmt);
		if (!unsigned_pointer_value(integer, pointer))
			return false;
		code = swap_comparison(code);
	}
	if (TREE_CODE(constant) != INTEGER_CST)
		return false;
	if (!truth)
		code = invert_comparison(code);
	if (code != GE_EXPR && code != GT_EXPR)
		return false;

	type = TREE_TYPE(integer);
	limit = wi::shwi(-MAX_ERRNO, TYPE_PRECISION(type));
	threshold = wi::to_wide(constant);
	if (code == GT_EXPR)
		limit = wi::sub(limit, 1);
	return wi::geu_p(threshold, limit);
}

static bool dominated_by_is_err(tree value, basic_block bb)
{
	tree pointer = converted_pointer(value);

	if (!pointer || !bb)
		return false;

	while (bb) {
		basic_block dom = get_immediate_dominator(CDI_DOMINATORS, bb);
		edge branch = NULL;
		edge e;
		edge_iterator ei;
		gimple stmt;
		bool truth;

		if (!dom)
			return false;
		FOR_EACH_EDGE(e, ei, dom->succs) {
			if (e->dest == bb ||
			    dominated_by_p(CDI_DOMINATORS, bb, e->dest)) {
				branch = e;
				break;
			}
		}
		if (!branch) {
			bb = dom;
			continue;
		}
		if (branch->flags & EDGE_TRUE_VALUE)
			truth = true;
		else if (branch->flags & EDGE_FALSE_VALUE)
			truth = false;
		else {
			bb = dom;
			continue;
		}
		stmt = last_stmt(dom);
		if (stmt && condition_implies_is_err(stmt, truth, pointer))
			return true;
		bb = dom;
	}
	return false;
}

#if BUILDING_GCC_VERSION >= 11000
static bool range_is_errno(tree value, gimple stmt, edge on_edge,
			   range_query *query)
{
	wide_int min_errno;
	wide_int max_errno;
	int_range_max range;
	tree type;
	unsigned int i;
	bool known;

	if (TREE_CODE(value) != SSA_NAME)
		return false;
	type = TREE_TYPE(value);
	if (!INTEGRAL_TYPE_P(type) || TYPE_UNSIGNED(type) ||
	    !irange::supports_p(type))
		return false;

	if (on_edge)
		known = query->range_on_edge(range, on_edge, value);
	else
		known = query->range_of_expr(range, value, stmt);
	if (!known || range.undefined_p() || range.varying_p())
		return false;

	min_errno = wi::shwi(-MAX_ERRNO, TYPE_PRECISION(type));
	max_errno = wi::minus_one(TYPE_PRECISION(type));
	for (i = 0; i < range.num_pairs(); i++)
		if (wi::lts_p(range.lower_bound(i), min_errno) ||
		    wi::gts_p(range.upper_bound(i), max_errno))
			return false;
	return range.num_pairs() != 0;
}
#endif

static bool value_may_be_errno(tree value, tree *seen, unsigned int depth,
			       gimple stmt, edge on_edge
#if BUILDING_GCC_VERSION >= 11000
			       , range_query *query
#endif
			       )
{
	gimple def;
	unsigned int i;

	if (!value || depth == MAX_VALUE_DEPTH)
		return false;
	if (is_errno_constant(value))
		return true;
	if (dominated_by_is_err(value, on_edge ? on_edge->src : gimple_bb(stmt)))
		return true;
#if BUILDING_GCC_VERSION >= 11000
	if (range_is_errno(value, stmt, on_edge, query))
		return true;
#endif
	if (TREE_CODE(value) != SSA_NAME)
		return false;

	for (i = 0; i < depth; i++)
		if (seen[i] == value)
			return false;
	seen[depth] = value;

	def = SSA_NAME_DEF_STMT(value);
	if (!def)
		return false;

	if (gimple_code(def) == GIMPLE_PHI) {
		gphi *phi = as_a_gphi(def);

		for (i = 0; i < gimple_phi_num_args(phi); i++)
			if (value_may_be_errno(gimple_phi_arg_def(phi, i), seen,
					       depth + 1, def,
					       gimple_phi_arg_edge(phi, i)
#if BUILDING_GCC_VERSION >= 11000
					       , query
#endif
					       ))
				return true;
		return false;
	}

	if (is_gimple_assign(def) &&
	    (gimple_assign_copy_p(def) || gimple_assign_cast_p(def)))
		return value_may_be_errno(gimple_assign_rhs1(def), seen,
					  depth + 1, def, on_edge
#if BUILDING_GCC_VERSION >= 11000
					  , query
#endif
					  );

	return false;
}

static bool function_may_return_errno(
#if BUILDING_GCC_VERSION >= 11000
				      range_query *query
#endif
				      )
{
	basic_block bb;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);
			tree seen[MAX_VALUE_DEPTH];
			tree value;

			if (gimple_code(stmt) != GIMPLE_RETURN)
				continue;
			value = gimple_return_retval(as_a_greturn(stmt));
			if (value_may_be_errno(value, seen, 0, stmt, NULL
#if BUILDING_GCC_VERSION >= 11000
					       , query
#endif
					       ))
				return true;
		}
	}

	return false;
}

static void emit_candidate(const char *name)
{
	unsigned int bytes = POINTER_SIZE / BITS_PER_UNIT;

	/* The relocation preserves the identity of local, same-named functions. */
	fputs("\t.pushsection .fmodret_candidates,\"\"\n", asm_out_file);
	fprintf(asm_out_file, "\t.balign %u\n", bytes);
	fprintf(asm_out_file, bytes == 8 ? "\t.quad %s\n" : "\t.long %s\n",
		name);
	fputs("\t.popsection\n", asm_out_file);
}

static unsigned int fmodret_candidates_execute(void)
{
	tree fndecl = current_function_decl;
	tree return_type;
	const char *asm_name;
	const char *name;
	bool candidate;
	bool had_dominators;
#if BUILDING_GCC_VERSION >= 11000
	gimple_ranger *ranger;
#endif

	if (!fndecl || DECL_EXTERNAL(fndecl) || DECL_ARTIFICIAL(fndecl))
		return 0;

	return_type = TREE_TYPE(TREE_TYPE(fndecl));
	if (!is_signed_int_or_long(return_type))
		return 0;

	had_dominators = dom_info_available_p(CDI_DOMINATORS);
	if (!had_dominators)
		calculate_dominance_info(CDI_DOMINATORS);
#if BUILDING_GCC_VERSION >= 11000
	ranger = enable_ranger(cfun);
	candidate = function_may_return_errno(ranger);
	disable_ranger(cfun);
#else
	candidate = function_may_return_errno();
#endif
	if (!had_dominators)
		free_dominance_info(CDI_DOMINATORS);
	if (!candidate)
		return 0;

	asm_name = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl));
	name = targetm.strip_name_encoding(asm_name);
	emit_candidate(name);
	return 0;
}

#define PASS_NAME fmodret_candidates
#define NO_GATE
#define PROPERTIES_REQUIRED (PROP_gimple_leh | PROP_cfg | PROP_ssa)
#define TODO_FLAGS_FINISH 0
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	const char *plugin_name = plugin_info->base_name;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}
	for (i = 0; i < plugin_info->argc; i++) {
		if (!strcmp(plugin_info->argv[i].key, "disable"))
			disable = true;
		else {
			error(G_("unknown option '-fplugin-arg-%s-%s'"),
			      plugin_name, plugin_info->argv[i].key);
			return 1;
		}
	}
	if (disable)
		return 0;

	PASS_INFO(fmodret_candidates, "optimized", 1,
		  PASS_POS_INSERT_BEFORE);
	register_callback(plugin_name, PLUGIN_INFO, NULL,
			  &fmodret_candidates_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
			  &fmodret_candidates_pass_info);
	return 0;
}
