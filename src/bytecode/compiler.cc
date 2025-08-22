#include "compiler.h"

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
  auto& variables = rule->variables();
  for (const auto& var : variables) {
    // Compile variable
    compileVariable(var.get(), program);
    const Register load_var_result_reg = Register::RDI;

    // Compile transformations
    Register transform_dst_reg = Register::RAX;
    Register transform_src_reg = load_var_result_reg;
    if (!rule->isIgnoreDefaultTransform() && default_action) {
      // Get the default transformation
      auto& transforms = default_action->transforms();
      for (auto& transform : transforms) {
        TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(), program);
        if (transform_src_reg == load_var_result_reg) {
          transform_src_reg = Register::RAX;
          transform_dst_reg = Register::RBX;
        } else {
          std::swap(transform_dst_reg, transform_src_reg);
        }
      }
    }
    auto& transforms = rule->transforms();
    for (auto& transform : transforms) {
      TransformCompiler::compile(transform_dst_reg, transform_src_reg, transform.get(), program);
      if (transform_src_reg == Register::RDI) {
        transform_src_reg = Register::RAX;
        transform_dst_reg = Register::RBX;
      } else {
        std::swap(transform_dst_reg, transform_src_reg);
      }
    }

    // Compile operator
    auto& op = rule->getOperator();
    compileOperator(op.get(), program);
  }

  // Compile each action in the rule
  auto& actions = rule->actions();
  for (const auto& action : actions) {
    compileAction(action.get(), program);
  }
}

void Compiler::compileVariable(const Variable::VariableBase* variable, Program& program) {
  VariableCompiler::compile(variable, program);
}

void Compiler::compileTransform(const Transformation::TransformBase* transform, Program& program) {}

void Compiler::compileOperator(const Operator::OperatorBase* op, Program& program) {}

void Compiler::compileAction(const Action::ActionBase* action, Program& program) {}
} // namespace Bytecode
} // namespace Wge