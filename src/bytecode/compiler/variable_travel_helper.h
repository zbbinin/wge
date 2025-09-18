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

// Macro to travel all variable types. The macro X will be expanded with each variable type as
// argument. This is used to generate code for all variable types to avoid loss or duplication of
// any variable type
// clang-format off
#define TRAVEL_VARIABLES(X)                            \
  X(ArgsCombinedSize)                                  \
  X(ArgsGetNames)                                      \
  X(ArgsGet)                                           \
  X(ArgsNames)                                         \
  X(ArgsPostNames)                                     \
  X(ArgsPost)                                          \
  X(Args)                                              \
  X(AuthType)                                          \
  X(Duration)                                          \
  X(Env)                                               \
  X(FilesCombinedSize)                                 \
  X(FilesNames)                                        \
  X(FilesSizes)                                        \
  X(FilesTmpContent)                                   \
  X(FilesTmpNames)                                     \
  X(Files)                                             \
  X(FullRequestLength)                                 \
  X(FullRequest)                                       \
  X(Geo)                                               \
  X(Global)                                            \
  X(HighestSeverity)                                   \
  X(InboundDataError)                                  \
  X(Ip)                                                \
  X(MatchedVarName)                                    \
  X(MatchedVar)                                        \
  X(MatchedVarsNames)                                  \
  X(MatchedVars)                                       \
  X(ModSecBuild)                                       \
  X(MscPcreLimitsExceeded)                             \
  X(MultipartBoundaryQuoted)                           \
  X(MultipartBoundaryWhitespace)                       \
  X(MultipartCrlfLfLines)                              \
  X(MultipartDataAfter)                                \
  X(MultipartDataBefore)                               \
  X(MultipartFileLimitExceeded)                        \
  X(MultipartFileName)                                 \
  X(MultipartHeaderFolding)                            \
  X(MultipartInvalidHeaderFolding)                     \
  X(MultipartInvalidPart)                              \
  X(MultipartInvalidQuoting)                           \
  X(MultipartLfLine)                                   \
  X(MultipartMissingSemicolon)                         \
  X(MultipartName)                                     \
  X(MultipartPartHeaders_IsCharSet)                    \
  X(MultipartPartHeaders_NotCharSet)                   \
  X(MultipartStrictError)                              \
  X(MultipartUnmatchedBoundary)                        \
  X(OutboundDataError)                                 \
  X(PathInfo)                                          \
  X(QueryString)                                       \
  X(RemoteAddr)                                        \
  X(RemoteHost)                                        \
  X(RemotePort)                                        \
  X(RemoteUser)                                        \
  X(ReqBodyErrorMsg)                                   \
  X(ReqBodyError)                                      \
  X(ReqbodyProcessorError)                             \
  X(ReqBodyProcessor)                                  \
  X(RequestBaseName)                                   \
  X(RequestBodyLength)                                 \
  X(RequestBody)                                       \
  X(RequestCookiesNames)                               \
  X(RequestCookies)                                    \
  X(RequestFileName)                                   \
  X(RequestHeadersNames)                               \
  X(RequestHeaders)                                    \
  X(RequestLine)                                       \
  X(RequestMothod)                                     \
  X(RequestProtocol)                                   \
  X(RequestUriRaw)                                     \
  X(RequestUri)                                        \
  X(Resource)                                          \
  X(ResponseBody)                                      \
  X(ResponseContentLength)                             \
  X(ResponseContentType)                               \
  X(ResponseHeadersNames)                              \
  X(ResponseHeaders)                                   \
  X(ResponseProtocol)                                  \
  X(ResponseStatus)                                    \
  X(Rule_Id)                                           \
  X(Rule_Phase)                                        \
  X(Rule_OperatorValue)                                \
  X(ServerAddr)                                        \
  X(ServerName)                                        \
  X(ServerPort)                                        \
  X(Session)                                           \
  X(SessionId)                                         \
  X(StatusLine)                                        \
  X(TimeDay)                                           \
  X(TimeEpoch)                                         \
  X(TimeHour)                                          \
  X(TimeMin)                                           \
  X(TimeMon)                                           \
  X(TimeSec)                                           \
  X(TimeWDay)                                          \
  X(TimeYear)                                          \
  X(Time)                                              \
  X(Tx_IsCaptureIndex)                                 \
  X(Tx_NotCaptureIndex)                                \
  X(UniqueId)                                          \
  X(UrlenCodedError)                                   \
  X(User)                                              \
  X(UserId)                                            \
  X(WebAppId)                                          \
  X(Xml_AttrValue)                                     \
  X(Xml_TagValue)                                      \
  X(Xml_AttrValuePmf)                                  \
  X(Xml_TagValuePmf)
// clang-format on

// Variable Alias
namespace Wge {
namespace Variable {
class MultipartPartHeaders;
class Rule;
class Tx;
class Xml;
using MultipartPartHeaders_IsCharSet = MultipartPartHeaders;
using MultipartPartHeaders_NotCharSet = MultipartPartHeaders;
using Rule_Id = Rule;
using Rule_Phase = Rule;
using Rule_OperatorValue = Rule;
using Tx_IsCaptureIndex = Tx;
using Tx_NotCaptureIndex = Tx;
using Xml_AttrValue = Xml;
using Xml_TagValue = Xml;
using Xml_AttrValuePmf = Xml;
using Xml_TagValuePmf = Xml;
} // namespace Variable
} // namespace Wge
