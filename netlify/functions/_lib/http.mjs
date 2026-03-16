export function jsonResponse(payload, statusCode = 200) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    },
    body: JSON.stringify(payload)
  };
}

export function errorResponse(message, statusCode = 400) {
  return jsonResponse({ error: message }, statusCode);
}

export function getQueryParams(event) {
  return event?.queryStringParameters || {};
}

export function parseJsonBody(event) {
  if (!event?.body) {
    throw new Error("Request body required");
  }
  try {
    return JSON.parse(event.body);
  } catch {
    throw new Error("Invalid JSON body");
  }
}
