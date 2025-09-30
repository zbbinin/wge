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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/TargetSelect.h>

#pragma GCC diagnostic pop

namespace Wge {
namespace Jit {
class LlvmWrapper {
public:
  LlvmWrapper();

public:
  template <class RetType, class... ArgTypes>
  void createCall(std::string_view name, void* func_ptr) const {
    std::vector<llvm::Type*> args;
    (args.emplace_back(getType<ArgTypes>()), ...);

    llvm::Type* ret_type = getType<RetType>();
    llvm::Function* func = llvm::Function::Create(llvm::FunctionType::get(ret_type, args, false),
                                                  llvm::Function::ExternalLinkage, name, *module_);
    engine_->addGlobalMapping(func, func_ptr);
  }

  template <auto MemberFunc> void createMemberCall(std::string_view name) {
    using MemberFuncType = decltype(MemberFunc);

    static_assert(std::is_member_function_pointer_v<MemberFuncType>,
                  "Template parameter must be a member function pointer");

    using ClassType = typename function_traits<MemberFuncType>::class_type;
    using RetType = typename function_traits<MemberFuncType>::return_type;
    std::vector<llvm::Type*> args = {getType<ClassType*>()};
    addMemberArgs<MemberFuncType>(
        args, std::make_index_sequence<function_traits<MemberFuncType>::arity>{});

    auto wrapper = createWrapper<MemberFunc, MemberFuncType>(
        std::make_index_sequence<function_traits<MemberFuncType>::arity>{});

    llvm::Type* ret_type = getType<RetType>();
    llvm::Function* func = llvm::Function::Create(llvm::FunctionType::get(ret_type, args, false),
                                                  llvm::Function::ExternalLinkage, name, *module_);

    engine_->addGlobalMapping(func, reinterpret_cast<void*>(wrapper));
  }

private:
  class InitHelper {
  public:
    InitHelper() {
      // Initialize LLVM targets
      llvm::InitializeNativeTarget();
      llvm::InitializeNativeTargetAsmPrinter();
      llvm::InitializeNativeTargetAsmParser();
    }
  };

  struct Types {
    llvm::Type* void_;
    llvm::Type* int64_t_;
    llvm::Type* ptr_;
    Types(llvm::LLVMContext& context) {
      void_ = llvm::Type::getVoidTy(context);
      int64_t_ = llvm::Type::getInt64Ty(context);
      ptr_ = int64_t_;
    }
  };

  template <typename T> struct function_traits;

  template <typename RetType, typename ClassType, typename... ArgTypes>
  struct function_traits<RetType (ClassType::*)(ArgTypes...)> {
    using return_type = RetType;
    using class_type = ClassType;
    using args_tuple = std::tuple<ArgTypes...>;
    static constexpr size_t arity = sizeof...(ArgTypes);

    template <size_t N> using arg_type = typename std::tuple_element<N, args_tuple>::type;
  };

private:
  template <class T> llvm::Type* getType() const {
    using DecayT = std::decay_t<T>;
    if constexpr (std::is_same_v<DecayT, void>) {
      return types_.void_;
    } else if constexpr (std::is_same_v<DecayT, int64_t>) {
      return types_.int64_t_;
    } else if constexpr (std::is_pointer_v<DecayT>) {
      return types_.ptr_;
    } else if constexpr (std::is_reference_v<T>) {
      return types_.ptr_;
    } else {
      static_assert(!std::is_same_v<DecayT, DecayT>, "Unsupported type");
    }
  }

  template <class MemberFuncType, size_t... Is>
  void addMemberArgs(std::vector<llvm::Type*>& args, std::index_sequence<Is...>) {
    (args.emplace_back(getType<typename function_traits<MemberFuncType>::template arg_type<Is>>()),
     ...);
  }

  template <auto MemberFunc, typename MemberFuncType, size_t... Is>
  auto createWrapper(std::index_sequence<Is...>) {
    using ClassType = typename function_traits<MemberFuncType>::class_type;
    using RetType = typename function_traits<MemberFuncType>::return_type;

    return +[](void* this_ptr,
               typename function_traits<MemberFuncType>::template arg_type<Is>... args) -> RetType {
      auto* obj = static_cast<ClassType*>(this_ptr);
      if constexpr (std::is_void_v<RetType>) {
        (obj->*MemberFunc)(args...);
      } else {
        return (obj->*MemberFunc)(args...);
      }
    };
  }

private:
  static InitHelper init_helper_;
  std::unique_ptr<llvm::LLVMContext> context_;
  std::unique_ptr<llvm::Module> module_;
  std::unique_ptr<llvm::IRBuilder<>> builder_;
  std::unique_ptr<llvm::ExecutionEngine> engine_;
  llvm::DataLayout data_layout_;
  Types types_{*context_};
};
} // namespace Jit
} // namespace Wge