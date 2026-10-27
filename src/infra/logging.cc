#include "infra/logging.h"

#include <cstdio>

namespace gatehouse::infra {
void LogOperationFailure(const char* operation) {
  std::fprintf(stderr, "[gatehouse][error] %s failed\n", operation);
}
}  // namespace gatehouse::infra
