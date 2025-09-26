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

// Macro to travel all transformation types. The macro X will be expanded with each transformation
// type as argument. This is used to generate code for all transformation types to avoid loss or
// duplication of any transformation type

#define TRAVEL_TRANSFORMATIONS(X)                                                                  \
  X(Base64DecodeExt)                                                                               \
  X(Base64Decode)                                                                                  \
  X(Base64Encode)                                                                                  \
  X(CmdLine)                                                                                       \
  X(CompressWhiteSpace)                                                                            \
  X(CssDecode)                                                                                     \
  X(EscapeSeqDecode)                                                                               \
  X(HexDecode)                                                                                     \
  X(HexEncode)                                                                                     \
  X(HtmlEntityDecode)                                                                              \
  X(JsDecode)                                                                                      \
  X(Length)                                                                                        \
  X(LowerCase)                                                                                     \
  X(Md5)                                                                                           \
  X(NormalisePathWin)                                                                              \
  X(NormalisePath)                                                                                 \
  X(NormalizePathWin)                                                                              \
  X(NormalizePath)                                                                                 \
  X(ParityEven7Bit)                                                                                \
  X(ParityOdd7Bit)                                                                                 \
  X(ParityZero7Bit)                                                                                \
  X(RemoveCommentsChar)                                                                            \
  X(RemoveComments)                                                                                \
  X(RemoveNulls)                                                                                   \
  X(RemoveWhitespace)                                                                              \
  X(ReplaceComments)                                                                               \
  X(ReplaceNulls)                                                                                  \
  X(Sha1)                                                                                          \
  X(SqlHexDecode)                                                                                  \
  X(TrimLeft)                                                                                      \
  X(TrimRight)                                                                                     \
  X(Trim)                                                                                          \
  X(UpperCase)                                                                                     \
  X(UrlDecodeUni)                                                                                  \
  X(UrlDecode)                                                                                     \
  X(UrlEncode)                                                                                     \
  X(Utf8ToUnicode)
