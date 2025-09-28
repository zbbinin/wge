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

// Macro to travel all action types. The macro X will be expanded with each action type as
// argument. This is used to generate code for all action types to avoid loss or duplication of
// any action type
#define TRAVEL_ACTIONS(X)                                                                          \
  X(Ctl)                                                                                           \
  X(InitCol)                                                                                       \
  X(SetEnv)                                                                                        \
  X(SetRsc)                                                                                        \
  X(SetSid)                                                                                        \
  X(SetUid)                                                                                        \
  X(SetVar_Create_TF)                                                                              \
  X(SetVar_Create_FF)                                                                              \
  X(SetVar_CreateAndInit_TT)                                                                       \
  X(SetVar_CreateAndInit_TF)                                                                       \
  X(SetVar_CreateAndInit_FT)                                                                       \
  X(SetVar_CreateAndInit_FF)                                                                       \
  X(SetVar_Remove_TF)                                                                              \
  X(SetVar_Remove_FF)                                                                              \
  X(SetVar_Increase_TT)                                                                            \
  X(SetVar_Increase_TF)                                                                            \
  X(SetVar_Increase_FT)                                                                            \
  X(SetVar_Increase_FF)                                                                            \
  X(SetVar_Decrease_TT)                                                                            \
  X(SetVar_Decrease_TF)                                                                            \
  X(SetVar_Decrease_FT)                                                                            \
  X(SetVar_Decrease_FF)

// Action Alias
namespace Wge {
namespace Action {
class SetVar;

// Naming convention: SetVar_{EvaluateType}_{IsKeyMacro(T|F)}_{IsValueMacro(T|F)}
using SetVar_Create_TF = SetVar;
using SetVar_Create_FF = SetVar;
using SetVar_CreateAndInit_TT = SetVar;
using SetVar_CreateAndInit_TF = SetVar;
using SetVar_CreateAndInit_FT = SetVar;
using SetVar_CreateAndInit_FF = SetVar;
using SetVar_Remove_TF = SetVar;
using SetVar_Remove_FF = SetVar;
using SetVar_Increase_TT = SetVar;
using SetVar_Increase_TF = SetVar;
using SetVar_Increase_FT = SetVar;
using SetVar_Increase_FF = SetVar;
using SetVar_Decrease_TT = SetVar;
using SetVar_Decrease_TF = SetVar;
using SetVar_Decrease_FT = SetVar;
using SetVar_Decrease_FF = SetVar;
} // namespace Action
} // namespace Wge
