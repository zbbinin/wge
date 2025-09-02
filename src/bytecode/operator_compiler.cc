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

#include "program.h"

#include "../operator/operator_include.h"

#define OPERATOR_INDEX(name)                                                                       \
  { Operator::name::name_, __COUNTER__ }

namespace Wge {
namespace Bytecode {
const std::unordered_map<const char*, int64_t> OperatorCompiler::operator_index_map_ = {
    OPERATOR_INDEX(BeginsWith),
    OPERATOR_INDEX(ContainsWord),
    OPERATOR_INDEX(Contains),
    OPERATOR_INDEX(DetectSqli),
    OPERATOR_INDEX(DetectXSS),
    OPERATOR_INDEX(EndsWith),
    OPERATOR_INDEX(Eq),
    OPERATOR_INDEX(FuzzyHash),
    OPERATOR_INDEX(Ge),
    OPERATOR_INDEX(GeoLookup),
    OPERATOR_INDEX(Gt),
    OPERATOR_INDEX(InspectFile),
    OPERATOR_INDEX(IpMatchFromFile),
    OPERATOR_INDEX(IpMatch),
    OPERATOR_INDEX(Le),
    OPERATOR_INDEX(Lt),
    OPERATOR_INDEX(NoMatch),
    OPERATOR_INDEX(PmFromFile),
    OPERATOR_INDEX(Pm),
    OPERATOR_INDEX(Rbl),
    OPERATOR_INDEX(Rsub),
    OPERATOR_INDEX(RxGlobal),
    OPERATOR_INDEX(Rx),
    OPERATOR_INDEX(Streq),
    OPERATOR_INDEX(Strmatch),
    OPERATOR_INDEX(UnconditionalMatch),
    OPERATOR_INDEX(ValidateByteRange),
    OPERATOR_INDEX(ValidateDTD),
    OPERATOR_INDEX(ValidateSchema),
    OPERATOR_INDEX(ValidateUrlEncoding),
    OPERATOR_INDEX(ValidateUtf8Encoding),
    OPERATOR_INDEX(VerifyCC),
    OPERATOR_INDEX(VerifyCPF),
    OPERATOR_INDEX(VerifySSN),
    OPERATOR_INDEX(Within),
};

void OperatorCompiler::compile(ExtraRegister res_reg, ExtraRegister src_reg,
                               const Operator::OperatorBase* op, Program& program) {
  auto iter = operator_index_map_.find(op->name());
  assert(iter != operator_index_map_.end());
  if (iter != operator_index_map_.end()) {
    int64_t index = iter->second;
    int64_t operator_ptr = reinterpret_cast<int64_t>(op);
    program.emit({OpCode::OPERATE,
                  {.ex_reg_ = res_reg},
                  {.ex_reg_ = src_reg},
                  {.index_ = index},
                  {.cptr_ = reinterpret_cast<const void*>(operator_ptr)}});
  }
}
} // namespace Bytecode
} // namespace Wge

#undef OPERATOR_INDEX