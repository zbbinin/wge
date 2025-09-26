#include "rule_compiler.h"

#include "action_compiler.h"
#include "macro_compiler.h"
#include "operator_compiler.h"
#include "transform_compiler.h"
#include "variable_compiler.h"

#include "../../common/log.h"
#include "../../engine.h"
#include "../../rule.h"

namespace Wge {
namespace Bytecode {
namespace Compiler {
std::unique_ptr<Program> RuleCompiler::compile(const Rule* rule, const Rule* default_action_rule,
                                               const Engine* engine) {
  auto program = std::make_unique<Program>();
  compileRule(rule, default_action_rule, engine, *program);
  return program;
}

std::unique_ptr<Program> RuleCompiler::compile(const std::vector<const Rule*>& rules,
                                               const Rule* default_action_rule,
                                               const Engine* engine) {
  auto program = std::make_unique<Program>();
  std::vector<SkipInfo> skip_info_array;
  for (const Rule* rule : rules) {
    compileRule(rule, default_action_rule, engine, *program, &skip_info_array);
  }
  return program;
}

void RuleCompiler::compileRule(const Rule* rule, const Rule* default_action_rule,
                               const Engine* engine, Program& program,
                               std::vector<SkipInfo>* skip_info_array) {
  // Update Skip info
  if (skip_info_array && rule->chainIndex() == -1) {
    updateSkipInfo(program, *skip_info_array, rule, engine);
  }

  auto& op = rule->getOperator();
  if (op == nullptr) {
    // Compile each uncondition action in the rule
    auto& actions = rule->actions();
    for (auto& action : actions) {
      Compiler::ActionCompiler::compileUncAction(action.get(), program);
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
      // Traverse the results of operator and do action
      // The run-time dummy code:
      // size_t i = 0;
      // LABEL:
      // if(i < results.size()) {
      //   pushMatched(results[i]);
      //
      //   action1->evaluate();
      //   action2->evaluate();
      //   ...
      //
      //   ++i;
      //   goto LABEL;
      // }
      program.emit({OpCode::SIZE, {.g_reg_ = loop_count_}, {.x_reg_ = op_res_reg_}});
      program.emit({OpCode::MOV, {.g_reg_ = loop_cursor_}, {.imm_ = 0}});
      size_t loop_start_label = program.instructions().size();
      program.emit({OpCode::CMP, {.g_reg_ = loop_cursor_}, {.g_reg_ = loop_count_}});
      size_t jz_index = program.instructions().size();
      program.emit({OpCode::JZ, {.address_ = RELOCATION}});

      if (rule->isNeedPushMatched()) {
        program.emit({OpCode::PUSH_MATCHED,
                      {.x_reg_ = op_src_reg},
                      {.x_reg_ = op_res_reg_},
                      {.g_reg_ = loop_cursor_}});
      }

      if (default_actions) {
        for (auto& action : *default_actions) {
          Compiler::ActionCompiler::compileAction(action.get(), op_res_reg_, program);
        }
      }
      for (auto& action : rule->actions()) {
        Compiler::ActionCompiler::compileAction(action.get(), op_res_reg_, program);
      }

      program.emit({OpCode::ADD, {.g_reg_ = loop_cursor_}, {.imm_ = 1}});
      program.emit({OpCode::JMP, {.address_ = static_cast<int64_t>(loop_start_label)}});
      program.relocate(jz_index, program.instructions().size());
    } else {
      // Push all matched
      if (rule->isNeedPushMatched()) {
        program.emit({OpCode::PUSH_ALL_MATCHED, {.x_reg_ = op_src_reg}, {.x_reg_ = op_res_reg_}});
      }
    }
  }

  // Skip the instuctions of chain rule if the OPERATE was not matched
  const size_t jnom_index_for_rule_matched = program.instructions().size();
  program.emit({OpCode::JNOM, {.address_ = RELOCATION}});

  // Compile chain rule
  std::optional<size_t> jnom_index_for_chain_matched;
  std::optional<std::list<std::unique_ptr<Rule>>::const_iterator> chain_rule_iter =
      rule->chainRule(0);
  if (chain_rule_iter.has_value()) {
    const Rule* chain_rule = (**chain_rule_iter).get();
    // Indicate the start of chain rule execution
    program.emit({OpCode::CHAIN_START, {.cptr_ = chain_rule}});

    // Compile chain rule
    compileRule(chain_rule, default_action_rule, engine, program);

    // Indicate the end of chain rule execution
    program.emit({OpCode::CHAIN_END, {.cptr_ = rule}});

    // If the chained rule are matched means the rule is matched, otherwise the rule is not
    // matched
    jnom_index_for_chain_matched = program.instructions().size();
    program.emit({OpCode::JNOM, {.address_ = RELOCATION}});
  }

  // Compile expand macro
  Compiler::MacroCompiler::compile(rule->msgMacro().get(), rule->logDataMacro().get(), program);

  if (rule->chainIndex() == -1) {
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
    if (engine->config().rule_engine_option_ != EngineConfig::Option::DetectionOnly) {
      program.emit({OpCode::EXIT_IF_DISRUPTIVE});
    }

    // Compile skip
    if (rule->skip() != 0 || !rule->skipAfter().empty()) {
      if (skip_info_array == nullptr) {
        WGE_LOG_CRITICAL("skip compile error: no skip info");
      } else {
        size_t jom_index = program.instructions().size();
        program.emit({OpCode::JOM, {.address_ = RELOCATION}});
        if (rule->skip() != 0) {
          skip_info_array->emplace_back(rule->skip(), jom_index);
        } else {
          skip_info_array->emplace_back(rule->skipAfter(), jom_index);
        }
      }
    }
  }

  // Relocate jump address
  const size_t curr_index = program.instructions().size();
  program.relocate(jnom_index_for_rule_matched, curr_index);
  if (jnom_index_for_chain_matched.has_value()) {
    program.relocate(jnom_index_for_chain_matched.value(), curr_index);
  }
  if (jmp_if_remove_index.has_value()) {
    program.relocate(jmp_if_remove_index.value(), curr_index);
  }
}

void RuleCompiler::updateSkipInfo(Program& program, std::vector<SkipInfo>& skip_info_array,
                                  const Rule* rule, const Engine* engine) {
  for (auto iter = skip_info_array.begin(); iter != skip_info_array.end();) {
    std::visit(
        [&](auto&& skip_info) {
          using T = std::decay_t<decltype(skip_info)>;
          if constexpr (std::is_same_v<T, int>) {
            if (skip_info == 0) {
              program.relocate(iter->jom_index_, program.instructions().size());
              iter = skip_info_array.erase(iter);
            } else {
              --skip_info;
              ++iter;
            }
          } else {
            auto next_rule_iter = engine->marker(skip_info, rule->phase());
            if (next_rule_iter.has_value() && rule == **next_rule_iter) {
              program.relocate(iter->jom_index_, program.instructions().size());
              iter = skip_info_array.erase(iter);
            } else {
              ++iter;
            }
          }
        },
        iter->target_);
  }
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge