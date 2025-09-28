/**
 * Copyright (c) 2024-2025 Stone Rhino and contributors.
 *
 * MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "action_compiler.h"

#include "action_travel_helper.h"

#include "../../action/actions_include.h"
#include "../../common/log.h"
#include "../program.h"

#define ACTION_OPCODE(action_type)                                                                 \
  {Action::action_type::name_, Wge::Bytecode::OpCode::ACTION_##action_type},

#define UNC_ACTION_OPCODE(action_type)                                                             \
  {Action::action_type::name_, Wge::Bytecode::OpCode::UNC_ACTION_##action_type},

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, OpCode> ActionCompiler::action_opcode_map_ = {
    TRAVEL_ACTIONS(ACTION_OPCODE)};
const std::unordered_map<const char*, OpCode> ActionCompiler::unc_action_opcode_map_ = {
    TRAVEL_ACTIONS(UNC_ACTION_OPCODE)};

void ActionCompiler::compileAction(const Action::ActionBase* action, ExtendedRegister op_res_reg,
                                   Program& program) {
  auto iter = action_opcode_map_.find(action->name());
  assert(iter != action_opcode_map_.end());
  if (iter == action_opcode_map_.end()) {
    UNREACHABLE();
    WGE_LOG_CRITICAL("action compile error: unknown action {}", action->name());
    return;
  }

  std::optional<OpCode> op_code = calcOpCode(action, iter->second);
  if (op_code.has_value()) {
    program.emit({op_code.value(), {.x_reg_ = op_res_reg}, {.cptr_ = action}});
  } else {
    UNREACHABLE();
    WGE_LOG_CRITICAL("action compile error: unknown opreator code {}", action->name());
    return;
  }
}

void ActionCompiler::compileUncAction(const Action::ActionBase* action, Program& program) {
  auto iter = unc_action_opcode_map_.find(action->name());
  assert(iter != unc_action_opcode_map_.end());
  if (iter == unc_action_opcode_map_.end()) {
    UNREACHABLE();
    WGE_LOG_CRITICAL("unc action compile error: unknown action {}", action->name());
    return;
  }

  std::optional<OpCode> op_code = calcOpCode(action, iter->second);
  if (op_code.has_value()) {
    program.emit({op_code.value(), {.cptr_ = action}});
  } else {
    UNREACHABLE();
    WGE_LOG_CRITICAL("action compile error: unknown opreator code {}", action->name());
    return;
  }
}

std::optional<OpCode> ActionCompiler::calcOpCode(const Action::ActionBase* action,
                                                 OpCode base_opcode) {
  std::optional<OpCode> real_opcode;
  switch (base_opcode) {
  case OpCode::ACTION_Ctl_AuditEngine: {
    auto p = dynamic_cast<const Action::Ctl*>(action);
    switch (p->type()) {
    case Action::Ctl::CtlType::AuditEngine: {
      real_opcode = OpCode::ACTION_Ctl_AuditEngine;
    } break;
    case Action::Ctl::CtlType::AuditLogParts: {
      real_opcode = OpCode::ACTION_Ctl_AuditLogParts;
    } break;
    case Action::Ctl::CtlType::ParseXmlIntoArgs: {
      real_opcode = OpCode::ACTION_Ctl_ParseXmlIntoArgs;
    } break;
    case Action::Ctl::CtlType::RequestBodyAccess: {
      real_opcode = OpCode::ACTION_Ctl_RequestBodyAccess;
    } break;
    case Action::Ctl::CtlType::RequestBodyProcessor: {
      real_opcode = OpCode::ACTION_Ctl_RequestBodyProcessor;
    } break;
    case Action::Ctl::CtlType::RuleEngine: {
      real_opcode = OpCode::ACTION_Ctl_RuleEngine;
    } break;
    case Action::Ctl::CtlType::RuleRemoveById: {
      real_opcode = OpCode::ACTION_Ctl_RuleRemoveById;
    } break;
    case Action::Ctl::CtlType::RuleRemoveByIdRange: {
      real_opcode = OpCode::ACTION_Ctl_RuleRemoveByIdRange;
    } break;
    case Action::Ctl::CtlType::RuleRemoveByTag: {
      real_opcode = OpCode::ACTION_Ctl_RuleRemoveByTag;
    } break;
    case Action::Ctl::CtlType::RuleRemoveTargetById: {
      real_opcode = OpCode::ACTION_Ctl_RuleRemoveTargetById;
    } break;
    case Action::Ctl::CtlType::RuleRemoveTargetByTag: {
      real_opcode = OpCode::ACTION_Ctl_RuleRemoveTargetByTag;
    } break;
    default:
      UNREACHABLE();
      break;
    }
  } break;
  case OpCode::ACTION_SetVar_Create_TF: {
    auto p = dynamic_cast<const Action::SetVar*>(action);
    bool is_key_macro = p->isKeyMacro();
    bool is_value_macro = p->isValueMacro();
    switch (p->type()) {
    case Action::SetVar::EvaluateType::Create: {
      if (is_key_macro) {
        real_opcode = OpCode::ACTION_SetVar_Create_TF;
      } else {
        real_opcode = OpCode::ACTION_SetVar_Create_FF;
      }
    } break;
    case Action::SetVar::EvaluateType::CreateAndInit: {
      if (is_key_macro) {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_CreateAndInit_TT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_CreateAndInit_TF;
        }
      } else {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_CreateAndInit_FT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_CreateAndInit_FF;
        }
      }
    } break;
    case Action::SetVar::EvaluateType::Remove: {
      if (is_key_macro) {
        real_opcode = OpCode::ACTION_SetVar_Remove_TF;
      } else {
        real_opcode = OpCode::ACTION_SetVar_Remove_FF;
      }
    } break;
    case Action::SetVar::EvaluateType::Increase: {
      if (is_key_macro) {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_Increase_TT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_Increase_TF;
        }
      } else {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_Increase_FT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_Increase_FF;
        }
      }
    } break;
    case Action::SetVar::EvaluateType::Decrease: {
      if (is_key_macro) {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_Decrease_TT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_Decrease_TF;
        }
      } else {
        if (is_value_macro) {
          real_opcode = OpCode::ACTION_SetVar_Decrease_FT;
        } else {
          real_opcode = OpCode::ACTION_SetVar_Decrease_FF;
        }
      }
    } break;
    default:
      UNREACHABLE();
      break;
    }
  } break;
  default:
    real_opcode = base_opcode;
    break;
  }

  return real_opcode;
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef ACTION_INDEX