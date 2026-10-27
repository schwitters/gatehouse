#pragma once

namespace gatehouse::infra {
// Report fixed operation names only; never pass credentials or request payloads.
void LogOperationFailure(const char* operation);
}  // namespace gatehouse::infra
