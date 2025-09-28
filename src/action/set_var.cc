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
#include "set_var.h"

namespace Wge {
namespace Action {
SetVar::SetVar(std::string&& key, size_t index, Common::Variant&& value, EvaluateType type)
    : key_(std::move(key)), index_(index), value_(std::move(value)), type_(type) {
  // Holds the string value of the variant
  if (IS_STRING_VIEW_VARIANT(value_)) {
    const_cast<std::string&>(value_buffer_) = std::get<std::string_view>(value_);
    const_cast<Common::Variant&>(value_) = value_buffer_;
  }
}

SetVar::SetVar(std::string&& key, size_t index, const std::shared_ptr<Macro::MacroBase> value,
               EvaluateType type)
    : key_(std::move(key)), index_(index), value_macro_(value), type_(type) {
  // Holds the string value of the variant
  if (IS_STRING_VIEW_VARIANT(value_)) {
    const_cast<std::string&>(value_buffer_) = std::get<std::string_view>(value_);
    const_cast<Common::Variant&>(value_) = value_buffer_;
  }
}

SetVar::SetVar(const std::shared_ptr<Macro::MacroBase> key, Common::Variant&& value,
               EvaluateType type)
    : key_macro_(key), value_(std::move(value)), type_(type) {
  // Holds the string value of the variant
  if (IS_STRING_VIEW_VARIANT(value_)) {
    const_cast<std::string&>(value_buffer_) = std::get<std::string_view>(value_);
    const_cast<Common::Variant&>(value_) = value_buffer_;
  }
}

SetVar::SetVar(const std::shared_ptr<Macro::MacroBase> key,
               const std::shared_ptr<Macro::MacroBase> value, EvaluateType type)
    : key_macro_(key), value_macro_(value), type_(type) {
  // Holds the string value of the variant
  if (IS_STRING_VIEW_VARIANT(value_)) {
    const_cast<std::string&>(value_buffer_) = std::get<std::string_view>(value_);
    const_cast<Common::Variant&>(value_) = value_buffer_;
  }
}

void SetVar::evaluate(Transaction& t) const {
  switch (type_) {
  case EvaluateType::Create: {
    if (key_macro_)
      [[unlikely]] { evaluate<EvaluateType::Create, true, false>(t); }
    else {
      evaluate<EvaluateType::Create, false, false>(t);
    }
  } break;
    [[likely]] case EvaluateType::CreateAndInit : {
      if (key_macro_)
        [[unlikely]] {
          if (value_macro_)
            [[unlikely]] { evaluate<EvaluateType::CreateAndInit, true, true>(t); }
          else {
            evaluate<EvaluateType::CreateAndInit, true, false>(t);
          }
        }
      else {
        if (value_macro_)
          [[unlikely]] { evaluate<EvaluateType::CreateAndInit, false, true>(t); }
        else {
          evaluate<EvaluateType::CreateAndInit, false, false>(t);
        }
      }
    }
    break;
  case EvaluateType::Remove: {
    if (key_macro_)
      [[unlikely]] { evaluate<EvaluateType::Remove, true, false>(t); }
    else {
      evaluate<EvaluateType::Remove, false, false>(t);
    }
  } break;
  case EvaluateType::Increase: {
    if (key_macro_)
      [[unlikely]] {
        if (value_macro_) {
          evaluate<EvaluateType::Increase, true, true>(t);
        } else {
          evaluate<EvaluateType::Increase, true, false>(t);
        }
      }
    else {
      if (value_macro_) {
        evaluate<EvaluateType::Increase, false, true>(t);
      } else {
        evaluate<EvaluateType::Increase, false, false>(t);
      }
    }
  } break;
  case EvaluateType::Decrease: {
    if (key_macro_)
      [[unlikely]] {
        if (value_macro_) {
          evaluate<EvaluateType::Decrease, true, true>(t);
        } else {
          evaluate<EvaluateType::Decrease, true, false>(t);
        }
      }
    else {
      if (value_macro_) {
        evaluate<EvaluateType::Decrease, false, true>(t);
      } else {
        evaluate<EvaluateType::Decrease, false, false>(t);
      }
    }
  } break;
  default:
    UNREACHABLE();
    break;
  }
}
} // namespace Action
} // namespace Wge