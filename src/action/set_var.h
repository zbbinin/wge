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

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "action_base.h"

#include "../common/assert.h"
#include "../common/log.h"
#include "../common/variant.h"
#include "../macro/macro_base.h"
#include "../transaction.h"

namespace Wge {
namespace Action {
/**
 * Creates, removes, or updates a variable. Variable names are case-insensitive.
 * Examples:
 * To create a variable and set its value to 1 (usually used for setting flags), use:
 * setvar:TX.score
 * To create a variable and initialize it at the same time, use: setvar:TX.score=10
 * To remove a variable, prefix the name with an exclamation mark: setvar:!TX.score
 * To increase or decrease variable value, use + and - characters in front of a numerical value:
 * setvar:TX.score=+5
 */
class SetVar final : public ActionBase {
  DECLARE_ACTION_NAME(setvar);

public:
  enum class EvaluateType { Create, CreateAndInit, Remove, Increase, Decrease };

public:
  SetVar(std::string&& key, size_t index, Common::Variant&& value, EvaluateType type);
  SetVar(std::string&& key, size_t index, const std::shared_ptr<Macro::MacroBase> value,
         EvaluateType type);
  SetVar(const std::shared_ptr<Macro::MacroBase> key, Common::Variant&& value, EvaluateType type);
  SetVar(const std::shared_ptr<Macro::MacroBase> key, const std::shared_ptr<Macro::MacroBase> value,
         EvaluateType type);

public:
  void evaluate(Transaction& t) const override;

public:
  const std::string& key() const { return key_; }
  const Common::Variant& value() const { return value_; }
  size_t index() const { return index_; }
  EvaluateType type() const { return type_; }
  bool isKeyMacro() const { return key_macro_ != nullptr; }
  bool isValueMacro() const { return value_macro_ != nullptr; }

public:
  template <EvaluateType type, bool is_key_macro, bool is_value_macro>
  void evaluate(Transaction& t) const {
    if constexpr (type == EvaluateType::Create) {
      if constexpr (is_key_macro) {
        Common::EvaluateResults result;
        key_macro_->evaluate(t, result);
        std::string_view key = std::get<std::string_view>(result.front().variant_);
        WGE_LOG_TRACE("setvar(Create): tx.{}=1", key);
        t.setVariable({key.data(), key.size()}, 1);
      } else {
        WGE_LOG_TRACE("setvar(Create): tx.{}[{}]=1", key_, index_);
        t.setVariable(index_, 1);
      }
    } else if constexpr (type == EvaluateType::CreateAndInit) {
      if constexpr (is_key_macro) {
        Common::EvaluateResults result;
        key_macro_->evaluate(t, result);
        std::string_view key = std::get<std::string_view>(result.front().variant_);
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          WGE_LOG_TRACE("setvar(CreateAndInit): tx.{}={}", key,
                        VISTIT_VARIANT_AS_STRING(result.front().variant_));
          t.setVariable({key.data(), key.size()}, result.front().variant_);
        } else {
          WGE_LOG_TRACE("setvar(CreateAndInit): tx.{}={}", key, VISTIT_VARIANT_AS_STRING(value_));
          t.setVariable({key.data(), key.size()}, Common::Variant(value_));
        }
      } else {
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          WGE_LOG_TRACE("setvar(CreateAndInit): tx.{}[{}]={}", key_, index_,
                        VISTIT_VARIANT_AS_STRING(result.front().variant_));
          t.setVariable(index_, result.front().variant_);
        } else {
          WGE_LOG_TRACE("setvar(CreateAndInit): tx.{}[{}]={}", key_, index_,
                        VISTIT_VARIANT_AS_STRING(value_));
          t.setVariable(index_, value_);
        }
      }
    } else if constexpr (type == EvaluateType::Remove) {
      if constexpr (is_key_macro) {
        Common::EvaluateResults result;
        key_macro_->evaluate(t, result);
        std::string_view key = std::get<std::string_view>(result.front().variant_);
        WGE_LOG_TRACE("setvar(Remove): tx.{}", key);
        t.removeVariable({key.data(), key.size()});
      } else {
        WGE_LOG_TRACE("setvar(Remove): tx.{}[{}]", key_, index_);
        t.removeVariable(index_);
      }
    } else if constexpr (type == EvaluateType::Increase) {
      if constexpr (is_key_macro) {
        Common::EvaluateResults result;
        key_macro_->evaluate(t, result);
        std::string_view key = std::get<std::string_view>(result.front().variant_);
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          int64_t value = std::get<int64_t>(result.front().variant_);
          WGE_LOG_TRACE("setvar(Increase): tx.{}+={}", key, value);
          t.increaseVariable({key.data(), key.size()}, value);
        } else {
          WGE_LOG_TRACE("setvar(Increase): tx.{}+={}", key, std::get<int64_t>(value_));
          t.increaseVariable({key.data(), key.size()}, std::get<int64_t>(value_));
        }
      } else {
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          int64_t value = std::get<int64_t>(result.front().variant_);
          WGE_LOG_TRACE("setvar(Increase): tx.{}[{}]+={}", key_, index_, value);
          t.increaseVariable(index_, value);
        } else {
          WGE_LOG_TRACE("setvar(Increase): tx.{}[{}]+={}", key_, index_, std::get<int64_t>(value_));
          t.increaseVariable(index_, std::get<int64_t>(value_));
        }
      }
    } else if constexpr (type == EvaluateType::Decrease) {
      if constexpr (is_key_macro) {
        Common::EvaluateResults result;
        key_macro_->evaluate(t, result);
        std::string_view key = std::get<std::string_view>(result.front().variant_);
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          int64_t value = std::get<int64_t>(result.front().variant_);
          WGE_LOG_TRACE("setvar(Decrease): tx.{}-={}", key, value);
          t.increaseVariable({key.data(), key.size()}, -value);
        } else {
          WGE_LOG_TRACE("setvar(Decrease): tx.{}-={}", key, std::get<int64_t>(value_));
          t.increaseVariable({key.data(), key.size()}, -std::get<int64_t>(value_));
        }
      } else {
        if constexpr (is_value_macro) {
          Common::EvaluateResults result;
          value_macro_->evaluate(t, result);
          int64_t value = std::get<int64_t>(result.front().variant_);
          WGE_LOG_TRACE("setvar(Decrease): tx.{}[{}]-={}", key_, index_, value);
          t.increaseVariable(index_, -value);
        } else {
          WGE_LOG_TRACE("setvar(Decrease): tx.{}[{}]-={}", key_, index_, std::get<int64_t>(value_));
          t.increaseVariable(index_, -std::get<int64_t>(value_));
        }
      }
    } else {
      UNREACHABLE();
    }
  }

private:
  std::string key_;
  size_t index_;
  const Common::Variant value_;
  const std::string value_buffer_;
  EvaluateType type_;
  const std::shared_ptr<Macro::MacroBase> key_macro_;
  const std::shared_ptr<Macro::MacroBase> value_macro_;
};
} // namespace Action
} // namespace Wge