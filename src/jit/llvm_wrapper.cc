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
#include "llvm_wrapper.h"

#include <llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h>

#include "../common/log.h"

namespace Wge {
namespace Jit {
LlvmWrapper::InitHelper LlvmWrapper::init_helper_;

LlvmWrapper::LlvmWrapper()
    : builder_(context_), data_layout_(llvm::orc::JITTargetMachineBuilder::detectHost()
                                           .get()
                                           .getDefaultDataLayoutForTarget()
                                           .get()),
      module_(std::make_unique<llvm::Module>("WGE_JIT_Module", context_)), types_(context_) {
  std::string error_str;
  module_->setDataLayout(data_layout_);
  engine_ = std::unique_ptr<llvm::ExecutionEngine>(llvm::EngineBuilder(std::move(module_))
                                                       .setErrorStr(&error_str)
                                                       .setEngineKind(llvm::EngineKind::JIT)
                                                       .setOptLevel(llvm::CodeGenOptLevel::Default)
                                                       .create());
  if (!engine_) {
    WGE_LOG_ERROR("Failed to create LLVM ExecutionEngine: {}", error_str);
  }
}
} // namespace Jit
} // namespace Wge