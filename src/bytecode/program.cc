#include "program.h"

#include "../common/log.h"

namespace Wge {
namespace Bytecode {
void Program::emit(const Instruction& instruction) {
  instructions_.emplace_back(instruction);
  WGE_LOG_TRACE("emit[{}]: {}", instructions_.size() - 1, instruction.toString());
}

void Program::relocate(size_t index, GeneralRegisterValue new_address) {
  if (index < instructions_.size()) {
    auto& instruction = instructions_[index];
    if (instruction.op_code_ != OpCode::JMP && instruction.op_code_ != OpCode::JZ &&
        instruction.op_code_ != OpCode::JNZ) {
      WGE_LOG_ERROR(
          "relocate jump address error: instruction at index {} is not a jump instruction", index);
      return;
    }

    instruction.op1_.address_ = new_address;
    WGE_LOG_TRACE("relocate: {}, {}", index, new_address);
  }
}

void Program::initActionInfo(
    int chain_index, const std::vector<std::unique_ptr<Action::ActionBase>>* default_actions,
    const std::vector<std::unique_ptr<Action::ActionBase>>* actions,
    std::function<int(Action::ActionBase*)> toIndexFunc) {
  auto iter = action_info_map_.find(chain_index);
  if (iter == action_info_map_.end()) {
    iter = action_info_map_.emplace(chain_index, std::vector<ActionInfo>()).first;
  }

  if (!iter->second.empty()) {
    return;
  }

  if (default_actions) {
    appendActionInfo(iter->second, *default_actions, toIndexFunc);
  }

  if (actions) {
    appendActionInfo(iter->second, *actions, toIndexFunc);
  }
}

const std::vector<Program::ActionInfo>* Program::actionInfos(int chain_index) const {
  auto iter = action_info_map_.find(chain_index);
  if (iter != action_info_map_.end()) {
    return &iter->second;
  }

  return nullptr;
}

void Program::appendActionInfo(std::vector<ActionInfo>& action_info,
                               const std::vector<std::unique_ptr<Action::ActionBase>>& actions,
                               std::function<int(Action::ActionBase*)> toIndexFunc) {
  for (const auto& action : actions) {
    int index = toIndexFunc(action.get());
    assert(index != -1);
    if (index != -1) {
      action_info.emplace_back(index, action.get());
    }
  }
}
} // namespace Bytecode
} // namespace Wge