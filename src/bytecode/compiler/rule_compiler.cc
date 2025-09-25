#include "rule_compiler.h"

#include "action_compiler.h"
#include "macro_compiler.h"
#include "operator_compiler.h"
#include "transform_compiler.h"
#include "variable_compiler.h"

#include "../../common/log.h"
#include "../../rule.h"

namespace Wge {
namespace Bytecode {
namespace Compiler {
std::unique_ptr<Program> RuleCompiler::compile(const Rule* rule, const Rule* default_action_rule,
                                               EngineConfig::Option rule_engine_option) {
  auto program = std::make_unique<Program>();
  compileRule(rule, default_action_rule, rule_engine_option, *program);
  return program;
}

std::unique_ptr<Program> RuleCompiler::compile(const std::vector<const Rule*>& rules,
                                               const Rule* default_action_rule,
                                               EngineConfig::Option rule_engine_option) {
  auto program = std::make_unique<Program>();
  for (const Rule* rule : rules) {
    compileRule(rule, default_action_rule, rule_engine_option, *program);
  }
  return program;
}

void RuleCompiler::compileRule(const Rule* rule, const Rule* default_action_rule,
                               EngineConfig::Option rule_engine_option, Program& program) {
  auto& op = rule->getOperator();
  if (op == nullptr) {
    // Initialize action infos
    Compiler::ActionCompiler::initProgramActionInfo(rule->chainIndex(), nullptr, &rule->actions(),
                                                    program);

    // Compile each uncondition action in the rule
    if (!rule->actions().empty()) {
      Compiler::ActionCompiler::compile(rule->chainIndex(), program);
    }
    return;
  }

  constexpr int64_t RELOCATION = -1;

  // Compile rule start
  std::optional<size_t> jmp_if_remove_index;
  if (rule->chainIndex() == -1) {
    program.emit({OpCode::RULE_START, {.cptr_ = rule}});
    jmp_if_remove_index = program.instructions().size();
    program.emit({OpCode::JMP_IF_REMOVED, {.address_ = RELOCATION}});
  }

  // Initialize action infos
  const auto default_actions = default_action_rule ? &default_action_rule->actions() : nullptr;
  Compiler::ActionCompiler::initProgramActionInfo(rule->chainIndex(), default_actions,
                                                  &rule->actions(), program);
  auto& variables = rule->variables();
  for (const auto& var : variables) {
    // Set current variable
    program.emit({OpCode::MOV, {.g_reg_ = curr_variable_reg_}, {.cptr_ = &var}});

    // Compile variable
    Compiler::VariableCompiler::compile(load_var_reg_, var.get(), program);

    // Compile transformations
    ExtendedRegister transform_dst_reg = transform_tmp_reg1_;
    ExtendedRegister transform_src_reg = load_var_reg_;
    if (!rule->isIgnoreDefaultTransform() && default_action_rule) {
      // Get the default transformation
      auto& transforms = default_action_rule->transforms();
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
    const ExtendedRegister op_src_reg = transform_src_reg;
    Compiler::OperatorCompiler::compile(op_res_reg_, op_src_reg, op.get(), program);

    // Compile actions
    if ((default_actions && !default_actions->empty()) || !rule->actions().empty()) {
      // Compile actions
      if (rule->isNeedPushMatched()) {
        Compiler::ActionCompiler::compile(rule->chainIndex(), op_src_reg, op_res_reg_, program);
      } else {
        Compiler::ActionCompiler::compile(rule->chainIndex(), op_res_reg_, program);
      }
    } else {
      // Push matched
      if (rule->isNeedPushMatched()) {
        program.emit({OpCode::PUSH_MATCHED, {.x_reg_ = op_src_reg}, {.x_reg_ = op_res_reg_}});
      }
    }
  }

  // Skip the instuctions of chain rule if the OPERATE was not matched
  const size_t jz_index_for_rule_matched = program.instructions().size();
  program.emit({OpCode::JZ, {.address_ = RELOCATION}});

  // Compile chain rule
  std::optional<size_t> jz_index_for_chain_matched;
  std::optional<std::list<std::unique_ptr<Rule>>::const_iterator> chain_rule_iter =
      rule->chainRule(0);
  if (chain_rule_iter.has_value()) {
    const Rule* chain_rule = (**chain_rule_iter).get();
    // Indicate the start of chain rule execution
    program.emit({OpCode::CHAIN, {.cptr_ = chain_rule}});

    // Compile chain rule
    compileRule(chain_rule, default_action_rule, rule_engine_option, program);

    // If the chained rule are matched means the rule is matched, otherwise the rule is not
    // matched
    jz_index_for_chain_matched = program.instructions().size();
    program.emit({OpCode::JZ, {.address_ = RELOCATION}});
  }

  // Compile expand macro
  Compiler::MacroCompiler::compile(rule->msgMacro().get(), rule->logDataMacro().get(), program);

  // Compile log callback
  if (default_action_rule) {
    if (rule->log().value_or(default_action_rule->log().value_or(true))) {
      program.emit({OpCode::LOG_CALLBACK});
    }
  } else {
    if (rule->log().value_or(true)) {
      program.emit({OpCode::LOG_CALLBACK});
    }
  }

  // Compile exit if disruptive
  if (rule_engine_option != EngineConfig::Option::DetectionOnly) {
    program.emit({OpCode::EXIT_IF_DISRUPTIVE});
  }

  // Relocate jump address
  const size_t curr_index = program.instructions().size();
  program.relocate(jz_index_for_rule_matched, curr_index);
  if (jz_index_for_chain_matched.has_value()) {
    program.relocate(jz_index_for_chain_matched.value(), curr_index);
  }
  if (jmp_if_remove_index.has_value()) {
    program.relocate(jmp_if_remove_index.value(), curr_index);
  }
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge