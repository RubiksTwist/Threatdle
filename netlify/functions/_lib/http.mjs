export function jsonResponse(payload, statusCode = 200) {
  return new Response(JSON.stringify(payload), {
    status: statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function errorResponse(message, statusCode = 500) {
  return jsonResponse({ error: message }, statusCode);
}

export function getQueryParams(request) {
  const url = new URL(request.url);
  return Object.fromEntries(url.searchParams.entries());
}

export async function parseJsonBody(request) {
  if (!request?.body) {
    throw new Error("Request body required");
  }
  try {
    return await request.json();
  } catch {
    throw new Error("Invalid JSON body");
  }
}
