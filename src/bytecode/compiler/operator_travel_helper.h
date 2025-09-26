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

// Macro to travel all operator types. The macro X will be expanded with each operator
// type as argument. This is used to generate code for all operator types to avoid loss or
// duplication of any operator type

#define TRAVEL_OPERATORS(X)                                                                        \
  X(BeginsWith)                                                                                    \
  X(ContainsWord)                                                                                  \
  X(Contains)                                                                                      \
  X(DetectSqli)                                                                                    \
  X(DetectXSS)                                                                                     \
  X(EndsWith)                                                                                      \
  X(Eq)                                                                                            \
  X(FuzzyHash)                                                                                     \
  X(Ge)                                                                                            \
  X(GeoLookup)                                                                                     \
  X(Gt)                                                                                            \
  X(InspectFile)                                                                                   \
  X(IpMatchFromFile)                                                                               \
  X(IpMatch)                                                                                       \
  X(Le)                                                                                            \
  X(Lt)                                                                                            \
  X(NoMatch)                                                                                       \
  X(PmFromFile)                                                                                    \
  X(Pm)                                                                                            \
  X(Rbl)                                                                                           \
  X(Rsub)                                                                                          \
  X(RxGlobal)                                                                                      \
  X(Rx)                                                                                            \
  X(Streq)                                                                                         \
  X(Strmatch)                                                                                      \
  X(UnconditionalMatch)                                                                            \
  X(ValidateByteRange)                                                                             \
  X(ValidateDTD)                                                                                   \
  X(ValidateSchema)                                                                                \
  X(ValidateUrlEncoding)                                                                           \
  X(ValidateUtf8Encoding)                                                                          \
  X(VerifyCC)                                                                                      \
  X(VerifyCPF)                                                                                     \
  X(VerifySSN)                                                                                     \
  X(Within)
