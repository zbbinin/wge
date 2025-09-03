#include "compiler.h"

#include "action_compiler.h"
#include "operator_compiler.h"
#include "transform_compiler.h"
#include "variable_compiler.h"

#include "../rule.h"

namespace Wge {
namespace Bytecode {

std::unique_ptr<Program> Compiler::compile(const std::vector<const Rule*>& rules,
                                           const Rule* default_action) {
  auto program = std::make_unique<Program>();

  // Compile each rule into program
  for (const Rule* rule : rules) {
    compileRule(rule, default_action, *program);
  }

  return program;
}

void Compiler::compileRule(const Rule* rule, const Rule* default_action, Program& program) {
  // Set current rule
  program.emit({OpCode::MOV, {.g_reg_ = curr_rule_reg_}, {.cptr_ = rule}});

  auto& variables = rule->variables();
  for (const auto& var : variables) {
    // Set current variable
    program.emit({OpCode::MOV, {.g_reg_ = curr_variable_reg_}, {.cptr_ = &var}});

    // Compile variable
    VariableCompiler::compile(var.get(), program);

    // Compile transformations
    ExtraRegister transform_dst_reg = transform_tmp_reg1_;
    ExtraRegister transform_src_reg = load_var_reg_;
    if (!rule->isIgnoreDefaultTransform() && default_action) {
      // Get the default transformation
      auto& transforms = default_action->transforms();
      for (auto& transform : transforms) {
        TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(), program);
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
      TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(), program);
      if (transform_src_reg == load_var_reg_) {
        transform_src_reg = transform_dst_reg;
        transform_dst_reg = transform_tmp_reg2_;
      } else {
        std::swap(transform_dst_reg, transform_src_reg);
      }
    }

    // Compile operator
    auto& op = rule->getOperator();
    if (op) {
      const ExtraRegister op_src_reg = transform_src_reg;
      OperatorCompiler::compile(op_res_reg_, op_src_reg, op.get(), program);

      // Set the transformed values register for action use
      program.emit({OpCode::MOV, {.g_reg_ = op_src_reg_}, {.ex_reg_ = op_src_reg}});

      // Compile each action in the rule
      auto& actions = rule->actions();
      for (const auto& action : actions) {
        ActionCompiler::compile(op_res_reg_, action.get(), program);
      }
    } else {
      // Compile each uncondition action in the rule
      auto& actions = rule->actions();
      for (const auto& action : actions) {
        ActionCompiler::compile(action.get(), program);
      }
    }
  }
}
} // namespace Bytecode
} // namespace Wge