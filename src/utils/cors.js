// src/utils/cors.js

export function getCorsHeaders(request, env = {}) {
  const allowedOrigins = [
    'https://aibarf.com',
    'http://localhost:8787' // For local development
  ];
  const origin = request.headers.get('Origin') || '';
  const allowedOrigin = allowedOrigins.includes(origin) ? origin : 'https://aibarf.com';

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}
