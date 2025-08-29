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
#include "transform_compiler.h"

#include "program.h"

#include "../transformation/transform_include.h"

#define TRANSFORM_INDEX(name)                                                                      \
  { Transformation::name::name_, __COUNTER__ }

namespace Wge {
namespace Bytecode {
const std::unordered_map<const char*, int64_t> TransformCompiler::transform_index_map_ = {
    TRANSFORM_INDEX(Base64DecodeExt),    TRANSFORM_INDEX(Base64Decode),
    TRANSFORM_INDEX(Base64Encode),       TRANSFORM_INDEX(CmdLine),
    TRANSFORM_INDEX(CompressWhiteSpace), TRANSFORM_INDEX(CssDecode),
    TRANSFORM_INDEX(EscapeSeqDecode),    TRANSFORM_INDEX(HexDecode),
    TRANSFORM_INDEX(HexEncode),          TRANSFORM_INDEX(HtmlEntityDecode),
    TRANSFORM_INDEX(JsDecode),           TRANSFORM_INDEX(Length),
    TRANSFORM_INDEX(LowerCase),          TRANSFORM_INDEX(Md5),
    TRANSFORM_INDEX(NormalisePathWin),   TRANSFORM_INDEX(NormalisePath),
    TRANSFORM_INDEX(NormalizePathWin),   TRANSFORM_INDEX(NormalizePath),
    TRANSFORM_INDEX(ParityEven7Bit),     TRANSFORM_INDEX(ParityOdd7Bit),
    TRANSFORM_INDEX(ParityZero7Bit),     TRANSFORM_INDEX(RemoveCommentsChar),
    TRANSFORM_INDEX(RemoveComments),     TRANSFORM_INDEX(RemoveNulls),
    TRANSFORM_INDEX(RemoveWhitespace),   TRANSFORM_INDEX(ReplaceComments),
    TRANSFORM_INDEX(ReplaceNulls),       TRANSFORM_INDEX(Sha1),
    TRANSFORM_INDEX(SqlHexDecode),       TRANSFORM_INDEX(TrimLeft),
    TRANSFORM_INDEX(TrimRight),          TRANSFORM_INDEX(Trim),
    TRANSFORM_INDEX(UpperCase),          TRANSFORM_INDEX(UrlDecodeUni),
    TRANSFORM_INDEX(UrlDecode),          TRANSFORM_INDEX(UrlEncode),
    TRANSFORM_INDEX(Utf8ToUnicode)};

void TransformCompiler::compile(ExtraRegister dst_reg, ExtraRegister src_reg,
                                const Transformation::TransformBase* transform, Program& program) {
  auto iter = transform_index_map_.find(transform->name());
  assert(iter != transform_index_map_.end());
  if (iter != transform_index_map_.end()) {
    int64_t index = iter->second;
    int64_t transform_ptr = reinterpret_cast<int64_t>(transform);
    program.emit({OpCode::TRANSFORM,
                  {.ex_reg_ = dst_reg},
                  {.ex_reg_ = src_reg},
                  {.index_ = index},
                  {.cptr_ = reinterpret_cast<const void*>(transform_ptr)}});
  }
}
} // namespace Bytecode
} // namespace Wge

#undef TRANSFORM_INDEX