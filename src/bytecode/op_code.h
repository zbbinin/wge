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

#include "compiler/variable_travel_helper.h"

namespace Wge {
namespace Bytecode {

/**
 * Bytecode operation codes for register-based rule evaluation
 * The bytecode provides a linear execution model that's more cache-friendly
 * and suitable for future JIT compilation
 */
enum class OpCode {
  // Set immediate value to destination register
  // Syntax: MOV <dst_reg>, <imm_value>
  // @param op1 [g_reg]: Destination register
  // @param op2 [imm]: Immediate value to set
  // Example: MOV RAX, 1
  MOV,

  // Unconditional jump
  // Syntax: JMP <target_addr>
  // @param op1 [address]: Target jump address
  // Example: JMP 123
  JMP,

  // Conditional jump if zero
  // Syntax: JZ <target_addr>
  // @param op1 [address]: Target jump address (jumps if RFLAGS == 0)
  // Example: JZ 123
  JZ,

  // Conditional jump if not zero
  // Syntax: JNZ <target_addr>
  // @param op1 [address]: Target jump address (jumps if RFLAGS != 0)
  // Example: JNZ 123
  JNZ,

  // No operation
  // Syntax: NOP
  // Example: NOP
  NOP,

  // Print debug information (for testing purposes)
  // Syntax: DEBUG <message>
  // @param op1 [cptr]: Constant pointer to message string
  // Example: DEBUG 123456
  DEBUG,

  // Load variable value into register
  // Syntax: LOAD_VAR <dst_reg>, <var_index>, <var_ptr>
  // @param op1 [x_reg]: Destination register
  // @param op2 [index]: Variable index in symbol table
  // @param op3 [cptr]: Constant pointer to variable instance
  // Example: LOAD_VAR RDI, 1, 0x123456
  LOAD_VAR,

  // Transform variable value.
  // Syntax: TRANSFORM <dst_reg>, <src_reg>, <transform_index>, <transform_instance_pointer>
  // @param op1 [x_reg]: Destination register
  // @param op2 [x_reg]: Source register
  // @param op3 [index]: Transformation index
  // @param op4 [cptr]: Constant pointer to transformation instance
  // Example:
  // TRANSFORM R9, R8, 1, 123456
  TRANSFORM,

  // Match variable value with operator.
  // Syntax: OPERATE <res_reg>  <src_reg>, <operator_index>, <operator_instance_pointer>
  // @param op1 [x_reg]: Result register
  // @param op2 [x_reg]: Source register
  // @param op3 [index]: Operator index
  // @param op4 [cptr]: Constant pointer to operator instance
  // Example:
  // OPERATE R11, R8, 1, 123456
  // Note: The RFLAGS indicate whether the operation was matched
  OPERATE,

  // Perform an action
  // Syntax: ACTION <src_reg>, <action_infos_pointer>
  // @param op1 [x_reg]: Source register(the input of the previous OPERATE)
  // @param op2 [x_reg]: Source register(the result of the previous OPERATE)
  // @param op2 [cptr]: An array of constant pointers specifying the action infos
  // (Program::ActionInfo)
  // Example:
  // ACTION R8, R11, 123456
  ACTION,

  // Perform an uncondition action
  // Syntax: UNC_ACTION <action_infos_pointer>
  // @param op1 [cptr]: An array of constant pointers specifying the action infos
  // (Program::ActionInfo)
  // Example:
  // UNC_ACTION 123456
  UNC_ACTION,

  // Expand msg macro and log macro
  // Syntax: EXPAND_MACRO <msg_macro_index> <msg_macro_instance_pointer> <log_macro_index>
  // <log_macro_instance_pointer>
  // @param op1 [index]: Msg macro index
  // @param op2 [cptr]: Constant pointer to msg macro instance
  // @param op3 [index]: Log macro index
  // @param op4 [cptr]: Constant pointer to log macro instance
  // Example:
  // EXPAND_MACRO 0 123456 1 654321
  EXPAND_MACRO,

  // Indicate the start of chain rule execution
  // Syntax: CHAIN
  // Example:
  // CHAIN
  CHAIN,

// ==================== Variable Loading Optimized Instructions ====================
// These instructions provide compile-time specialized versions of LOAD_VAR
// for specific variable types and access patterns, eliminating runtime dispatch
// overhead and enabling better JIT compilation optimization.
//
// Naming convention: LOAD_{VARIABLE_TYPE}_{C|V}{C|S|R}
// - C/V: Counter or Value mode
// - C/S/R: Collection, Specific subname, or Regex collection
//
// Parameters follow same convention as LOAD_VAR:
// @param op1 [x_reg]: Destination register
// @param op2 [index]: Variable index (for compatibility, may be unused)
// @param op3 [cptr]: Constant pointer to variable instance

// clang-format off
#define LOAD_VAR_INSTRUCTIONS(var_type)                      \
  LOAD_##var_type##_CC, /* Counter Collection */             \
  LOAD_##var_type##_CS, /* Counter Specific */               \
  LOAD_##var_type##_VC, /* Value Collection */               \
  LOAD_##var_type##_VR, /* Value Regex Collection */         \
  LOAD_##var_type##_VS, /* Value Specific */
  // clang-format on

  // Variable loading instructions for different types
  TRAVEL_VARIABLES(LOAD_VAR_INSTRUCTIONS)
};

static constexpr OpCode LOAD_VAR_INSTRUCTIONS_START = OpCode::LOAD_ArgsCombinedSize_CC;
static constexpr OpCode LOAD_VAR_INSTRUCTIONS_END = OpCode::LOAD_Xml_TagValuePmf_VS;

inline OpCode operator+(OpCode lhs, int rhs) {
  return static_cast<OpCode>(static_cast<int>(lhs) + rhs);
}
} // namespace Bytecode
} // namespace Wge