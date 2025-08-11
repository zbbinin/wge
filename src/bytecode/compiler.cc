#include "compiler.h"

#include "../rule.h"

namespace Wge {
namespace Bytecode {

std::unique_ptr<Program> Compiler::compile(const std::vector<const Rule*>& rules) {
  auto program = std::make_unique<Program>();

  // Compile each rule into program
  for (const Rule* rule : rules) {
    compileRule(rule, *program);
  }

  return program;
}

void Compiler::compileRule(const Rule* rule, Program& program) {
  // Compile each variable in the rule
  auto& variables = rule->variables();
  for (const auto& var : variables) {
    compileVariable(var.get(), program);
  }

  // Compile operator
  auto& op = rule->getOperator();
  compileOperator(op.get(), program);

  // Compile each action in the rule
  auto& actions = rule->actions();
  for (const auto& action : actions) {
    compileAction(action.get(), program);
  }
}

void Compiler::compileVariable(const Variable::VariableBase* variable, Program& program) {}

void Compiler::compileOperator(const Operator::OperatorBase* op, Program& program) {}

void Compiler::compileAction(const Action::ActionBase* action, Program& program) {}
} // namespace Bytecode
} // namespace Wge