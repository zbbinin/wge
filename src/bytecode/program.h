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
#pragma once

#include <functional>
#include <vector>

#include <boost/unordered/unordered_flat_map.hpp>

#include "instruction.h"

namespace Wge {
class Rule;
namespace Action {
class ActionBase;
} // namespace Action
} // namespace Wge

namespace Wge {
namespace Bytecode {
/**
 * Bytecode program represents a compiled rule or set of rules
 */
class Program {
public:
  Program(const Rule* rule = nullptr) : rule_(rule) {
    // Preallocate space for instructions
    instructions_.reserve(64);
  }

public:
  // Information about actions used in the program
  struct ActionInfo {
    int index_;                        // Action index in the action table
    const Action::ActionBase* action_; // Pointer to the action instance
    ActionInfo(int index, const Action::ActionBase* action) : index_(index), action_(action) {}
  };

public:
  /**
   * Add instruction to the program
   * @param instruction The instruction to add
   */
  void emit(const Instruction& instruction);

  /**
   * Relocate jump address. Such as updating the target address of JMP, JZ, JNZ instructions
   * @param index The index of the instruction to update
   * @param new_address The new address to set
   */
  void relocate(size_t index, GeneralRegisterValue new_address);

  /**
   * Get the list of instructions in the program
   * @return vector of instructions
   */
  const std::vector<Instruction>& instructions() const { return instructions_; }

  /**
   * Initialize action info list
   * @param chain_index The chain index of the rule
   * @param default_actions The default actions
   * @param actions The actions that are defined in the rule
   */
  void initActionInfo(int chain_index,
                      const std::vector<std::unique_ptr<Action::ActionBase>>* default_actions,
                      const std::vector<std::unique_ptr<Action::ActionBase>>* actions,
                      std::function<int(Action::ActionBase*)> toIndexFunc);

  /**
   * Get the action info list
   * @param chain_index The chain index of the rule
   * @return The action info list
   */
  const std::vector<ActionInfo>* actionInfos(int chain_index) const;

  /**
   * Get the rule associated with the program
   * @return The rule
   */
  const Rule* rule() const { return rule_; }

private:
  void appendActionInfo(std::vector<ActionInfo>& action_info,
                        const std::vector<std::unique_ptr<Action::ActionBase>>& actions,
                        std::function<int(Action::ActionBase*)> toIndexFunc);

private:
  const Rule* rule_{nullptr};
  std::vector<Instruction> instructions_;
  boost::unordered_flat_map<int, std::vector<ActionInfo>> action_info_map_;
};
} // namespace Bytecode
} // namespace Wge