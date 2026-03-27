#pragma once
#include <string>
#include <functional>
#include <memory>
#include "session.h"

namespace http {
namespace server {

	class ISseHandler {
	public:
		virtual ~ISseHandler() = default;

		// Called once the SSE stream HTTP headers have been sent.
		virtual void Start() = 0;

		// Called when the client disconnects or the server shuts down.
		virtual void Stop() = 0;

		// Called to check liveness (return false to trigger cleanup).
		virtual bool IsAlive() const = 0;
	};

	// Factory: given a writer function, the authenticated session from the HTTP request,
	// and an optional context string (e.g. MCP session ID), create a handler.
	using SseHandlerFactory = std::function<
		std::shared_ptr<ISseHandler>(
			std::function<void(const std::string&)> writer,  // writes raw bytes to socket
			const WebEmSession&                     session,
			const std::string&                      context  // sse_context from reply
		)
	>;

} // namespace server
} // namespace http
