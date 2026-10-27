#pragma once

#include "app/server_context.h"
#include "core/provisioning.h"

namespace gatehouse::app {
[[nodiscard]] core::Result<void> CompleteInvitation(
    ServerContext& context, const core::ProvisionRequest& request);
}  // namespace gatehouse::app
