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
#include "variable_compiler.h"

#include "variable_travel_helper.h"

#include "../../common/log.h"
#include "../../variable/variables_include.h"
#include "../program.h"

// clang-format off
#define VARIABLE_OPCODE(var_type)                                                                                       \
  {Variable::var_type::main_name_.data(), Wge::Bytecode::OpCode::LOAD_##var_type##_CC },
// clang-format on

namespace Wge {
namespace Bytecode {
namespace Compiler {
const std::unordered_map<const char*, OpCode> VariableCompiler::variable_opcode_map_ = {
    TRAVEL_VARIABLES(VARIABLE_OPCODE)};

void VariableCompiler::compile(ExtendedRegister dst_reg, const Variable::VariableBase* variable,
                               Program& program) {
  auto iter = variable_opcode_map_.find(variable->mainName().data());
  assert(iter != variable_opcode_map_.end());
  if (iter == variable_opcode_map_.end()) {
    UNREACHABLE();
    WGE_LOG_CRITICAL("variable compile error: unknown variable {}",
                     variable->fullName().tostring());
    return;
  }

  std::optional<OpCode> op_code = calcOpCode(variable, iter->second);
  if (op_code.has_value()) {
    program.emit({op_code.value(), {.x_reg_ = dst_reg}, {.cptr_ = variable}});
  } else {
    UNREACHABLE();
    WGE_LOG_CRITICAL("variable compile error: unknown opreator code {}",
                     variable->fullName().tostring());
    return;
  }
}

std::optional<OpCode> VariableCompiler::calcOpCode(const Variable::VariableBase* variable,
                                                   OpCode base_opcode) {
  // Calculate the offset based on whether it's a counter and collection
  // CC: Counter Collection
  // CS: Counter Specify
  // VC: Value Collection
  // VR: Value Regex Collection
  // VS: Value Specify
  int offset = 0;
  if (variable->isCounter()) {
    offset = variable->isCollection() ? 0 : 1; // CC : CS
  } else {
    if (variable->isCollection()) {
      offset = 2; // VC
    } else {
      const Variable::CollectionBase* p = dynamic_cast<const Variable::CollectionBase*>(variable);
      offset = p && p->isRegex() ? 3 : 4; // VR : VS
    }
  }

  // Adjust base_opcode for special variable types
  std::optional<OpCode> real_base_opcode;
  switch (base_opcode) {
  case OpCode::LOAD_MultipartPartHeaders_IsCharSet_CC: {
    auto p = dynamic_cast<const Variable::MultipartPartHeaders*>(variable);
    if (p->isCharset()) {
      real_base_opcode = OpCode::LOAD_MultipartPartHeaders_IsCharSet_CC;
    } else {
      real_base_opcode = OpCode::LOAD_MultipartPartHeaders_NotCharSet_CC;
    }
  } break;
  case OpCode::LOAD_Rule_Id_CC: {
    auto p = dynamic_cast<const Variable::Rule*>(variable);
    switch (p->subNameType()) {
    case Variable::Rule::SubNameType::Id:
      real_base_opcode = OpCode::LOAD_Rule_Id_CC;
      break;
    case Variable::Rule::SubNameType::Phase:
      real_base_opcode = OpCode::LOAD_Rule_Phase_CC;
      break;
    case Variable::Rule::SubNameType::OperatorValue:
      real_base_opcode = OpCode::LOAD_Rule_OperatorValue_CC;
      break;
    default:
      UNREACHABLE();
      break;
    }
  } break;
  case OpCode::LOAD_Tx_IsCaptureIndex_CC: {
    auto p = dynamic_cast<const Variable::Tx*>(variable);
    if (p->captureIndex().has_value()) {
      real_base_opcode = OpCode::LOAD_Tx_IsCaptureIndex_CC;
    } else {
      real_base_opcode = OpCode::LOAD_Tx_NotCaptureIndex_CC;
    }
  } break;
  case OpCode::LOAD_Xml_AttrValue_CC: {
    auto p = dynamic_cast<const Variable::Xml*>(variable);
    switch (p->type()) {
    case Variable::Xml::Type::AttrValue:
      real_base_opcode = OpCode::LOAD_Xml_AttrValue_CC;
      break;
    case Variable::Xml::Type::TagValue:
      real_base_opcode = OpCode::LOAD_Xml_TagValue_CC;
      break;
    case Variable::Xml::Type::AttrValuePmf:
      real_base_opcode = OpCode::LOAD_Xml_AttrValuePmf_CC;
      break;
    case Variable::Xml::Type::TagValuePmf:
      real_base_opcode = OpCode::LOAD_Xml_TagValuePmf_CC;
      break;
    default:
      UNREACHABLE();
      break;
    }
  } break;
  default:
    real_base_opcode = base_opcode;
    break;
  }

  if (real_base_opcode.has_value()) {
    return real_base_opcode.value() + offset;
  }

  return std::nullopt;
}
} // namespace Compiler
} // namespace Bytecode
} // namespace Wge

#undef VAR_TYPE_INFO