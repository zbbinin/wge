#include "rule_compiler.h"

#include "action_compiler.h"
#include "macro_compiler.h"
#include "operator_compiler.h"
#include "transform_compiler.h"
#include "variable_compiler.h"

#include "../../rule.h"

namespace Wge {
namespace Bytecode {
namespace Compiler {
std::unique_ptr<Program> RuleCompiler::compile(const Rule* rule, const Rule* default_action) {
  auto program = std::make_unique<Program>();
  compileRule(rule, default_action, *program);
  return program;
}

void RuleCompiler::compileRule(const Rule* rule, const Rule* default_action, Program& program) {
  auto& op = rule->getOperator();
  if (op == nullptr) {
    // Compile each uncondition action in the rule
    auto& actions = rule->actions();
    for (const auto& action : actions) {
      Compiler::ActionCompiler::compile(action.get(), program);
    }
    return;
  }

  // Set current rule
  program.emit({OpCode::MOV, {.g_reg_ = curr_rule_reg_}, {.cptr_ = rule}});

  auto& variables = rule->variables();
  for (const auto& var : variables) {
    // Set current variable
    program.emit({OpCode::MOV, {.g_reg_ = curr_variable_reg_}, {.cptr_ = &var}});

    // Compile variable
    Compiler::VariableCompiler::compile(var.get(), program);

    // Compile transformations
    ExtraRegister transform_dst_reg = transform_tmp_reg1_;
    ExtraRegister transform_src_reg = load_var_reg_;
    if (!rule->isIgnoreDefaultTransform() && default_action) {
      // Get the default transformation
      auto& transforms = default_action->transforms();
      for (auto& transform : transforms) {
        Compiler::TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(),
                                             program);
        if (transform_src_reg == load_var_reg_) {
          transform_src_reg = transform_dst_reg;
          transform_dst_reg = transform_tmp_reg2_;
        } else {
          std::swap(transform_dst_reg, transform_src_reg);
        }
      }
    }
    auto& transforms = rule->transforms();
    for (auto& transform : transforms) {
      Compiler::TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(),
                                           program);
      if (transform_src_reg == load_var_reg_) {
        transform_src_reg = transform_dst_reg;
        transform_dst_reg = transform_tmp_reg2_;
      } else {
        std::swap(transform_dst_reg, transform_src_reg);
      }
    }

    // Compile operator
    const ExtraRegister op_src_reg = transform_src_reg;
    Compiler::OperatorCompiler::compile(op_res_reg_, op_src_reg, op.get(), program);

    // Set the transformed values register for action use
    program.emit({OpCode::MOV, {.g_reg_ = op_src_reg_}, {.ex_reg_ = op_src_reg}});

    // Compile each default action
    if (default_action) {
      auto& actions = default_action->actions();
      for (const auto& action : actions) {
        Compiler::ActionCompiler::compile(op_res_reg_, action.get(), program);
      }
    }

    // Compile each action in the rule
    auto& actions = rule->actions();
    for (const auto& action : actions) {
      Compiler::ActionCompiler::compile(op_res_reg_, action.get(), program);
    }
  }

  // Skip the instuctions of chain rule if the OPERATE was not matched
  constexpr int64_t relocation = -1;
  const size_t jz_index = program.instructions().size();
  program.emit({OpCode::JZ, {.address_ = relocation}});

  // Compile chain rule
  std::optional<std::list<std::unique_ptr<Rule>>::const_iterator> chain_rule_iter =
      rule->chainRule(0);
  if (chain_rule_iter.has_value()) {
    // Compile chain rule
    const Rule* chain_rule = (**chain_rule_iter).get();
    compileRule(chain_rule, default_action, program);

    // Restore current rule
    program.emit({OpCode::MOV, {.g_reg_ = curr_rule_reg_}, {.cptr_ = rule}});
  }

  // Compile expand macro
  Compiler::MacroCompiler::compile(rule->msgMacro().get(), rule->logDataMacro().get(), program);

  // Relocate jump address
  const size_t curr_index = program.instructions().size();
  program.relocate(jz_index, curr_index);
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge