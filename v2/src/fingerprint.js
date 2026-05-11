// src/fingerprint.js — Framework and bundler detection
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const FRAMEWORK_SIGS = {
    React:   [/React\.createElement/,/ReactDOM\.render/,/jsx\(/,/_jsx\(/,/react-dom/,/__REACT_DEVTOOLS/],
    Vue:     [/Vue\.component/,/new Vue\(/,/createApp\(/,/__vue__/,/v-bind:|v-model/],
    Angular: [/@angular\/core/,/ng-version/,/NgModule/,/platformBrowserDynamic/],
    Svelte:  [/svelte\/internal/,/SvelteComponent/,/create_fragment/],
    Next:    [/__NEXT_DATA__/,/next\/router/,/next\/link/,/_next\/static/],
    Nuxt:    [/__NUXT__/,/nuxt\.config/,/NuxtChild/],
    Ember:   [/Ember\.Application/,/Ember\.Route/,/ember-cli/],
    jQuery:  [/jQuery\s+v|\.fn\.jquery/]
  };

  const BUNDLER_SIGS = {
    Webpack: [/__webpack_require__/,/webpackJsonp/,/webpackChunk/,/__webpack_modules__/],
    Vite:    [/@vite\/client/,/import\.meta\.hot/,/\/@fs\//],
    Parcel:  [/parcelRequire/,/__parcel__/],
    Rollup:  [/\(function\s*\(\)\s*\{\s*'use strict'/],
    esbuild: [/__esm\(/,/__toESM\(/,/__commonJS\(/]
  };

  JSA.fingerprint = function (code) {
    const result = { framework: null, bundler: null, details: {} };

    for (const [name, patterns] of Object.entries(FRAMEWORK_SIGS)) {
      const matches = patterns.filter(p => p.test(code)).length;
      if (matches >= 1) {
        if (!result.framework || matches > (result.details.fwMatches || 0)) {
          result.framework = name;
          result.details.fwMatches = matches;
        }
      }
    }

    for (const [name, patterns] of Object.entries(BUNDLER_SIGS)) {
      if (patterns.some(p => p.test(code))) {
        result.bundler = name;
        break;
      }
    }

    return result;
  };
})();
