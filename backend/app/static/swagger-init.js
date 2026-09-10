// Self-hosted so /api/docs needs no 'unsafe-inline' in its CSP (DX-13).
// Kept as its own file rather than an inline <script> block in main.py.
window.addEventListener('DOMContentLoaded', function () {
  window.ui = SwaggerUIBundle({
    url: '/api/openapi.json',
    dom_id: '#swagger-ui',
    layout: 'BaseLayout',
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  });
});
