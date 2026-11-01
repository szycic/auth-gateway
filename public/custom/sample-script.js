/**
 * Sample custom script for Auth Gateway service injection.
 *
 * Custom scripts can be injected into upstream services by adding their path
 * to the service's `injectScripts` array in config.json:
 *
 *   "injectScripts": [
 *     "/auth/assets/custom/sample-script.js"
 *   ]
 *
 * Custom scripts are served with CORS enabled from public/custom/
 * (mounted to /usr/src/app/public/custom in docker-compose.yml).
 */
(function() {
  console.log('[Auth Gateway] Custom sample script injected and loaded successfully.');
})();
