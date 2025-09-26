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
#include "operator_compiler.h"

#include "operator_travel_helper.h"

#include "../../operator/operator_include.h"
#include "../program.h"

#define OPERATOR_OPCODE(operator_type)                                                             \
  {Operator::operator_type::name_, Wge::Bytecode::OpCode::OPERATOR_##operator_type},

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, OpCode> OperatorCompiler::operator_opcode_map_ = {
    TRAVEL_OPERATORS(OPERATOR_OPCODE)};

void OperatorCompiler::compile(ExtendedRegister res_reg, ExtendedRegister src_reg,
                               const Operator::OperatorBase* op, Program& program) {
  auto iter = operator_opcode_map_.find(op->name());
  assert(iter != operator_opcode_map_.end());
  if (iter != operator_opcode_map_.end()) {
    program.emit({iter->second, {.x_reg_ = res_reg}, {.x_reg_ = src_reg}, {.cptr_ = op}});
  }
}

} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef OPERATOR_INDEX