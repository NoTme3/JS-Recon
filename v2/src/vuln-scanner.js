// src/vuln-scanner.js — Retire.js-style Vulnerable Dependency Scanner for JS Recon
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  // ─── LIBRARY SIGNATURE DATABASE ───
  // Each entry: regex signatures for content, filename patterns, CDN patterns,
  // known SHA-256 hashes for popular minified versions, and CVE list.
  const VULN_DB = [
    // ── jQuery ──
    {
      name: 'jQuery', icon: '',
      signatures: [
        /jQuery\s+(?:JavaScript\s+Library\s+)?v?([\d]+\.[\d]+\.[\d]+)/i,
        /jquery[.\-]?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*jQuery\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /jquery(?:\.min)?\.js\s*[|/]\s*v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/jquery[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min|\.slim)?\.js/i],
      cdnPatterns: [/\/jquery(?:\/|@)([\d]+\.[\d]+\.[\d]+)\//i],
      hashes: {
        'sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=': '3.3.1',
        'sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=': '3.6.0'
      },
      vulnerabilities: [
        {
          id: 'CVE-2020-11022', severity: 'medium',
          title: 'XSS via HTML passed to DOM manipulation methods',
          affected: ['1.2.0', '3.4.9'], fixed: '3.5.0',
          description: 'Passing HTML from untrusted sources to jQuery DOM manipulation methods (.html(), .append(), etc.) can execute untrusted code.',
          exploit: '$(\'\u003cimg/x onerror=alert(1) src=x\u003e\')',
          mitigation: 'Upgrade to jQuery >= 3.5.0. Sanitize all HTML before passing to jQuery methods.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11022', 'https://github.com/advisories/GHSA-gxr4-xjj5-5px2']
        },
        {
          id: 'CVE-2020-11023', severity: 'medium',
          title: 'XSS via \u003coption\u003e element passed to DOM manipulation',
          affected: ['1.0.3', '3.4.9'], fixed: '3.5.0',
          description: 'Passing HTML containing \u003coption\u003e elements from untrusted sources can execute untrusted code.',
          exploit: '$("\u003coption\u003e\u003cstyle\u003e\u003c/option\u003e\u003cimg src=x onerror=alert(1)\u003e")',
          mitigation: 'Upgrade to jQuery >= 3.5.0.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11023']
        },
        {
          id: 'CVE-2019-11358', severity: 'medium',
          title: 'Prototype Pollution in jQuery.extend',
          affected: ['1.0.0', '3.3.9'], fixed: '3.4.0',
          description: 'jQuery.extend(true, {}, ...) is vulnerable to Object.prototype pollution.',
          exploit: '$.extend(true, {}, JSON.parse(\'{"__proto__":{"isAdmin":true}}\'))',
          mitigation: 'Upgrade to jQuery >= 3.4.0.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-11358']
        },
        {
          id: 'CVE-2015-9251', severity: 'medium',
          title: 'XSS when Content-Type is text/javascript',
          affected: ['1.0.0', '2.9.9'], fixed: '3.0.0',
          description: 'jQuery before 3.0.0 is vulnerable to XSS when AJAX responses return text/javascript.',
          exploit: 'Cross-domain AJAX with Content-Type: text/javascript',
          mitigation: 'Upgrade to jQuery >= 3.0.0.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2015-9251']
        }
      ]
    },

    // ── Lodash ──
    {
      name: 'Lodash', icon: '',
      signatures: [
        /lodash\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*lodash\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /lodash[.\-]?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/lodash[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      cdnPatterns: [/\/lodash(?:\.js)?(?:\/|@)([\d]+\.[\d]+\.[\d]+)\//i],
      vulnerabilities: [
        {
          id: 'CVE-2021-23337', severity: 'high',
          title: 'Command Injection via template function',
          affected: ['0.0.1', '4.17.20'], fixed: '4.17.21',
          description: 'Lodash template function allows command injection through the variable option.',
          exploit: '_.template("", {variable: "x=1;process.mainModule.require(\'child_process\').execSync(\'id\')//"})()',
          mitigation: 'Upgrade to Lodash >= 4.17.21.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337']
        },
        {
          id: 'CVE-2020-28500', severity: 'medium',
          title: 'ReDoS via toNumber, trim, trimEnd',
          affected: ['0.0.1', '4.17.20'], fixed: '4.17.21',
          description: 'Lodash is vulnerable to ReDoS through toNumber, trim, and trimEnd functions.',
          exploit: '_.trim("  " + "\\t".repeat(50000) + "x")',
          mitigation: 'Upgrade to Lodash >= 4.17.21.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-28500']
        },
        {
          id: 'CVE-2020-8203', severity: 'high',
          title: 'Prototype Pollution via zipObjectDeep',
          affected: ['0.0.1', '4.17.18'], fixed: '4.17.19',
          description: 'Prototype pollution through zipObjectDeep with user-controlled data.',
          exploit: '_.zipObjectDeep(["__proto__.isAdmin"], [true])',
          mitigation: 'Upgrade to Lodash >= 4.17.19.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203']
        },
        {
          id: 'CVE-2019-10744', severity: 'critical',
          title: 'Prototype Pollution via defaultsDeep',
          affected: ['0.0.1', '4.17.11'], fixed: '4.17.12',
          description: 'Lodash defaultsDeep can add/modify Object.prototype properties via malicious payload.',
          exploit: '_.defaultsDeep({}, JSON.parse(\'{"__proto__":{"isAdmin":true}}\'))',
          mitigation: 'Upgrade to Lodash >= 4.17.12.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-10744']
        }
      ]
    },

    // ── AngularJS (1.x) ──
    {
      name: 'AngularJS', icon: '',
      signatures: [
        /AngularJS\s+v?(1\.[\d]+\.[\d]+)/i,
        /angular[.\-]?(1\.[\d]+\.[\d]+)/i,
        /\*!\s*angular\s+v?(1\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/angular[.-]?(1\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      cdnPatterns: [/\/angular(?:\.js)?(?:\/|@)(1\.[\d]+\.[\d]+)\//i],
      vulnerabilities: [
        {
          id: 'CVE-2022-25869', severity: 'medium',
          title: 'XSS via $sanitize service bypass',
          affected: ['1.0.0', '1.8.3'], fixed: null,
          description: 'AngularJS 1.x is end-of-life (Dec 2021). The $sanitize service can be bypassed.',
          exploit: '\u003cimg src=x ng-on-error=alert(1)\u003e',
          mitigation: 'Migrate to Angular (v2+). AngularJS 1.x is end-of-life.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-25869']
        },
        {
          id: 'CVE-2020-7676', severity: 'medium',
          title: 'XSS via angular.merge Prototype Pollution',
          affected: ['1.0.0', '1.7.9'], fixed: '1.8.0',
          description: 'angular.merge does not prevent prototype pollution leading to stored XSS.',
          exploit: 'angular.merge({}, JSON.parse(\'{"__proto__":{"innerHTML":"..."}}\'))',
          mitigation: 'Upgrade to AngularJS >= 1.8.0 or migrate to Angular 2+.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-7676']
        }
      ]
    },

    // ── React ──
    {
      name: 'React', icon: '',
      signatures: [
        /react(?:\.production|\.development)?(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i,
        /React\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*react\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /"version":\s*"([\d]+\.[\d]+\.[\d]+)"[^}]*?"name":\s*"react"/i,
        /"name":\s*"react"[^}]*?"version":\s*"([\d]+\.[\d]+\.[\d]+)"/i
      ],
      filePatterns: [/react[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.production|\.development)?(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2018-6341', severity: 'medium',
          title: 'XSS via href/action attribute in SSR',
          affected: ['16.0.0', '16.4.1'], fixed: '16.4.2',
          description: 'React SSR could be exploited for XSS via user-controlled URLs in href/action.',
          exploit: '\u003ca href="javascript:alert(1)"\u003eclick\u003c/a\u003e',
          mitigation: 'Upgrade to React >= 16.4.2. Sanitize user-provided URLs.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2018-6341']
        }
      ]
    },

    // ── Vue.js ──
    {
      name: 'Vue.js', icon: '',
      signatures: [
        /Vue\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*vue\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /vue(?:\.runtime)?(?:\.global|\.esm)?(?:\.prod)?(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/vue[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2024-6783', severity: 'medium',
          title: 'XSS via v-bind with user-controlled attribute names',
          affected: ['3.0.0', '3.4.37'], fixed: '3.4.38',
          description: 'Vue.js allows XSS if attribute names in v-bind are user-controlled.',
          exploit: '\u003cdiv v-bind:[userControlledAttr]="value"\u003e',
          mitigation: 'Upgrade to Vue >= 3.4.38.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-6783']
        },
        {
          id: 'CVE-2024-6783-v2', severity: 'medium',
          title: 'XSS via template compilation (Vue 2.x)',
          affected: ['2.0.0', '2.7.16'], fixed: null,
          description: 'Vue 2.x allows XSS via compiled untrusted templates. Vue 2.x is end-of-life (Dec 2023).',
          exploit: 'new Vue({template: userControlledString})',
          mitigation: 'Migrate to Vue 3. Never compile untrusted templates.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-6783']
        }
      ]
    },

    // ── Moment.js ──
    {
      name: 'Moment.js', icon: '',
      signatures: [
        /moment(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*moment\.js\s*[|\-]?\s*v?([\d]+\.[\d]+\.[\d]+)/i,
        /moment\s+version\s+:?\s*([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/moment[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2022-31129', severity: 'high',
          title: 'ReDoS via string-to-date parsing',
          affected: ['2.0.0', '2.29.3'], fixed: '2.29.4',
          description: 'Moment.js ReDoS when parsing user-provided date strings.',
          exploit: 'moment("a]".repeat(50000) + "!")',
          mitigation: 'Upgrade to Moment.js >= 2.29.4 or migrate to Luxon/Day.js.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-31129']
        },
        {
          id: 'CVE-2022-24785', severity: 'high',
          title: 'Path Traversal in moment.locale',
          affected: ['2.0.0', '2.29.1'], fixed: '2.29.2',
          description: 'Path traversal in Moment.js locale-loading mechanism.',
          exploit: 'moment.locale("../../etc/passwd")',
          mitigation: 'Upgrade to Moment.js >= 2.29.2.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-24785']
        }
      ]
    },

    // ── Handlebars.js ──
    {
      name: 'Handlebars', icon: '',
      signatures: [
        /handlebars\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*handlebars\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/handlebars[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2021-23369', severity: 'critical',
          title: 'Remote Code Execution via template compilation',
          affected: ['0.0.1', '4.7.6'], fixed: '4.7.7',
          description: 'Handlebars allows RCE when compiling templates with compat mode.',
          exploit: 'Handlebars.compile("{{#with ...}}")({})',
          mitigation: 'Upgrade to Handlebars >= 4.7.7.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23369']
        },
        {
          id: 'CVE-2019-19919', severity: 'critical',
          title: 'Prototype Pollution leading to RCE',
          affected: ['0.0.1', '4.3.0'], fixed: '4.3.1',
          description: 'Handlebars prototype pollution can be leveraged for RCE.',
          exploit: '{{#with "constructor"}}{{#with split as |a|}}...{{/with}}{{/with}}',
          mitigation: 'Upgrade to Handlebars >= 4.3.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-19919']
        }
      ]
    },

    // ── Underscore.js ──
    {
      name: 'Underscore.js', icon: '',
      signatures: [
        /Underscore\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*underscore\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/underscore[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2021-23358', severity: 'high',
          title: 'Arbitrary Code Execution via template function',
          affected: ['0.0.1', '1.13.0'], fixed: '1.13.1',
          description: 'The underscore template function can execute arbitrary code via attacker-controlled variable option.',
          exploit: '_.template("", {variable: "x=1;...execSync(\'id\')//"})()',
          mitigation: 'Upgrade to Underscore >= 1.13.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23358']
        }
      ]
    },

    // ── Bootstrap ──
    {
      name: 'Bootstrap', icon: '',
      signatures: [
        /Bootstrap\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*Bootstrap\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /bootstrap(?:\.min)?\.js\s*[|/]\s*v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/bootstrap[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2019-8331', severity: 'medium',
          title: 'XSS in tooltip/popover data-template',
          affected: ['3.0.0', '4.3.0'], fixed: '4.3.1',
          description: 'Bootstrap tooltip and popover plugins allow XSS via data-template.',
          exploit: '\u003cbutton data-toggle="tooltip" data-template="\u003cimg src=x onerror=alert(1)\u003e"\u003e',
          mitigation: 'Upgrade to Bootstrap >= 4.3.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-8331']
        },
        {
          id: 'CVE-2018-14040', severity: 'medium',
          title: 'XSS in collapse data-parent',
          affected: ['3.0.0', '4.1.1'], fixed: '4.1.2',
          description: 'Bootstrap collapse plugin allows XSS via data-parent.',
          exploit: '\u003cdiv data-toggle="collapse" data-parent="..."\u003e',
          mitigation: 'Upgrade to Bootstrap >= 4.1.2.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2018-14040']
        }
      ]
    },

    // ── DOMPurify ──
    {
      name: 'DOMPurify', icon: '',
      signatures: [
        /DOMPurify\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*DOMPurify\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /purify(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/(?:dompurify|purify)[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2024-47875', severity: 'critical',
          title: 'mXSS via Namespace Confusion',
          affected: ['0.0.1', '3.1.2'], fixed: '3.1.3',
          description: 'DOMPurify bypass via mutation-based XSS using namespace confusion.',
          exploit: '\u003cform\u003e\u003cmath\u003e\u003cmtext\u003e...\u003cimg src onerror=alert(1)\u003e',
          mitigation: 'Upgrade to DOMPurify >= 3.1.3.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-47875']
        }
      ]
    },

    // ── Axios ──
    {
      name: 'Axios', icon: '',
      signatures: [
        /axios\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*axios\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /"name":\s*"axios"[^}]*?"version":\s*"([\d]+\.[\d]+\.[\d]+)"/i
      ],
      filePatterns: [/axios[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2023-45857', severity: 'high',
          title: 'CSRF via XSRF-TOKEN cookie exposure',
          affected: ['0.8.1', '1.6.1'], fixed: '1.6.2',
          description: 'Axios leaks XSRF-TOKEN cookie in headers to third-party hosts on cross-domain requests.',
          exploit: 'Cross-origin axios request automatically includes XSRF-TOKEN header',
          mitigation: 'Upgrade to Axios >= 1.6.2.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-45857']
        }
      ]
    },

    // ── Socket.IO Client ──
    {
      name: 'Socket.IO Client', icon: '',
      signatures: [
        /socket\.io[- ]client\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*socket\.io-client\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      vulnerabilities: [
        {
          id: 'CVE-2024-38355', severity: 'high',
          title: 'Denial of Service via crafted payload',
          affected: ['0.0.1', '4.7.4'], fixed: '4.7.5',
          description: 'Socket.IO client vulnerable to DoS via crafted binary payload.',
          exploit: 'Crafted binary payload sent to the client',
          mitigation: 'Upgrade to Socket.IO Client >= 4.7.5.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-38355']
        }
      ]
    },

    // ── Knockout.js ──
    {
      name: 'Knockout', icon: '',
      signatures: [
        /Knockout\s+JavaScript\s+library\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /knockout[.\-]?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/knockout[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2019-14862', severity: 'medium',
          title: 'XSS via ko.utils.parseHtmlFragment',
          affected: ['0.0.1', '3.5.0'], fixed: '3.5.1',
          description: 'Knockout parseHtmlFragment allows XSS when processing user HTML.',
          exploit: 'ko.utils.parseHtmlFragment("\u003cimg src=x onerror=alert(1)\u003e")',
          mitigation: 'Upgrade to Knockout >= 3.5.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-14862']
        }
      ]
    },

    // ── Ember.js ──
    {
      name: 'Ember.js', icon: '',
      signatures: [
        /Ember\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*ember\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/ember[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2021-4142', severity: 'medium',
          title: 'XSS via component names in development mode',
          affected: ['3.0.0', '3.28.11'], fixed: '3.28.12',
          description: 'Ember.js dev mode shows user-controlled component names in error pages → XSS.',
          exploit: 'Dynamic component rendering with user-controlled name',
          mitigation: 'Upgrade to Ember >= 3.28.12.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-4142']
        }
      ]
    },

    // ══════════════════════════════════════════════
    // NEW LIBRARIES (retire.js-style additions)
    // ══════════════════════════════════════════════

    // ── D3.js ──
    {
      name: 'D3.js', icon: '',
      signatures: [
        /d3\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*d3\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /d3\.js\s*[,-]\s*v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/d3[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      cdnPatterns: [/\/d3(?:\.js)?(?:\/|@)([\d]+\.[\d]+\.[\d]+)\//i],
      vulnerabilities: [
        {
          id: 'CVE-2020-36401', severity: 'medium',
          title: 'Prototype Pollution in d3-color',
          affected: ['3.0.0', '5.16.0'], fixed: '6.0.0',
          description: 'D3 color module is vulnerable to prototype pollution.',
          exploit: 'd3.color({toString: Object.prototype.constructor})',
          mitigation: 'Upgrade to D3 >= 6.0.0.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-36401']
        }
      ]
    },

    // ── Marked.js ──
    {
      name: 'Marked', icon: '',
      signatures: [
        /marked\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*marked\s*[-–]\s*v?([\d]+\.[\d]+\.[\d]+)/i,
        /marked(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/marked[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2022-21680', severity: 'high',
          title: 'ReDoS in heading parsing',
          affected: ['0.0.1', '4.0.9'], fixed: '4.0.10',
          description: 'Marked.js ReDoS via crafted headings in Markdown input.',
          exploit: 'marked.parse("# " + "a]".repeat(1000))',
          mitigation: 'Upgrade to Marked >= 4.0.10.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-21680']
        },
        {
          id: 'CVE-2022-21681', severity: 'high',
          title: 'ReDoS in inline code parsing',
          affected: ['0.0.1', '4.0.9'], fixed: '4.0.10',
          description: 'Marked.js ReDoS via crafted inline code blocks.',
          exploit: 'marked.parse("`" + "\\t".repeat(10000) + "`")',
          mitigation: 'Upgrade to Marked >= 4.0.10.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-21681']
        }
      ]
    },

    // ── Highlight.js ──
    {
      name: 'Highlight.js', icon: '',
      signatures: [
        /highlight\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*highlight\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /hljs[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/highlight[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2021-32760', severity: 'medium',
          title: 'ReDoS in multiple language grammars',
          affected: ['9.0.0', '10.4.0'], fixed: '10.4.1',
          description: 'Highlight.js ReDoS via crafted source code in certain language grammars.',
          exploit: 'hljs.highlight("lang", "..." + "a".repeat(100000))',
          mitigation: 'Upgrade to Highlight.js >= 10.4.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-32760']
        }
      ]
    },

    // ── TinyMCE ──
    {
      name: 'TinyMCE', icon: '',
      signatures: [
        /tinymce\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /TinyMCE\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*tinymce\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/tinymce[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2024-29203', severity: 'medium',
          title: 'XSS via noscript element parsing',
          affected: ['6.0.0', '6.8.0'], fixed: '6.8.1',
          description: 'TinyMCE XSS via noscript element parsing in the editor.',
          exploit: '\u003cnoscript\u003e\u003c/noscript\u003e\u003cimg src=x onerror=alert(1)\u003e',
          mitigation: 'Upgrade to TinyMCE >= 6.8.1.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-29203']
        },
        {
          id: 'CVE-2022-23494', severity: 'medium',
          title: 'XSS via inserttable plugin',
          affected: ['5.0.0', '5.10.8'], fixed: '5.10.9',
          description: 'TinyMCE inserttable plugin allows XSS via crafted content.',
          exploit: 'Crafted content via paste into editor with inserttable plugin',
          mitigation: 'Upgrade to TinyMCE >= 5.10.9.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-23494']
        }
      ]
    },

    // ── CKEditor 4 ──
    {
      name: 'CKEditor', icon: '',
      signatures: [
        /CKEditor\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*CKEditor\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /CKEDITOR\.version\s*=\s*['"]([\d]+\.[\d]+\.[\d]+)['"]/i
      ],
      filePatterns: [/ckeditor[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2024-24816', severity: 'medium',
          title: 'XSS in samples with editor preview',
          affected: ['4.0.0', '4.24.0'], fixed: '4.25.0',
          description: 'CKEditor 4 samples are vulnerable to XSS via editor preview functionality.',
          exploit: 'Crafted HTML injected via CKEditor samples',
          mitigation: 'Upgrade to CKEditor >= 4.25.0 or remove samples in production.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-24816']
        },
        {
          id: 'CVE-2021-33829', severity: 'medium',
          title: 'XSS via clipboard module',
          affected: ['4.0.0', '4.16.1'], fixed: '4.16.2',
          description: 'CKEditor 4 allows XSS via the clipboard module.',
          exploit: 'Malicious clipboard content with HTML payload',
          mitigation: 'Upgrade to CKEditor >= 4.16.2.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-33829']
        }
      ]
    },

    // ── Prototype.js ──
    {
      name: 'Prototype.js', icon: '',
      signatures: [
        /Prototype\s+JavaScript\s+framework,\s+version\s+([\d]+\.[\d]+\.[\d]+)/i,
        /Prototype\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/prototype[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2020-27511', severity: 'high',
          title: 'Prototype Pollution in Object.extend',
          affected: ['1.0.0', '1.7.3'], fixed: null,
          description: 'Prototype.js Object.extend is vulnerable to prototype pollution. Library is unmaintained.',
          exploit: 'Object.extend({}, JSON.parse(\'{"__proto__":{"isAdmin":true}}\'))',
          mitigation: 'Migrate away from Prototype.js. It is no longer maintained.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-27511']
        }
      ]
    },

    // ── Backbone.js ──
    {
      name: 'Backbone.js', icon: '',
      signatures: [
        /Backbone\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*Backbone\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/backbone[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2016-9917', severity: 'medium',
          title: 'XSS in Model#escape method',
          affected: ['0.0.1', '1.2.3'], fixed: '1.3.0',
          description: 'Backbone.js Model#escape does not properly escape all HTML entities.',
          exploit: 'model.set("name", "\u003cimg onerror=alert(1) src=x\u003e")',
          mitigation: 'Upgrade to Backbone >= 1.3.0.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2016-9917']
        }
      ]
    },

    // ── EJS ──
    {
      name: 'EJS', icon: '',
      signatures: [
        /EJS\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*ejs\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /ejs(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/ejs[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2022-29078', severity: 'critical',
          title: 'Server-side Template Injection (RCE)',
          affected: ['0.0.1', '3.1.6'], fixed: '3.1.7',
          description: 'EJS template engine allows SSTI leading to remote code execution.',
          exploit: 'ejs.render("<%- include(\'/etc/passwd\') %>")',
          mitigation: 'Upgrade to EJS >= 3.1.7. Never pass user input as template options.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-29078']
        }
      ]
    },

    // ── Dojo ──
    {
      name: 'Dojo', icon: '',
      signatures: [
        /dojo\.version\s*=\s*\{[^}]*major:\s*(\d+),\s*minor:\s*(\d+),\s*patch:\s*(\d+)/i,
        /Dojo\s+v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/dojo[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2020-5258', severity: 'high',
          title: 'Prototype Pollution in dojo/_base/lang',
          affected: ['1.0.0', '1.16.3'], fixed: '1.16.4',
          description: 'Dojo is vulnerable to prototype pollution through its lang.setObject function.',
          exploit: 'dojo._base.lang.setObject("__proto__.polluted", true)',
          mitigation: 'Upgrade to Dojo >= 1.16.4.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-5258']
        }
      ]
    },

    // ── Chart.js ──
    {
      name: 'Chart.js', icon: '',
      signatures: [
        /Chart\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /\*!\s*Chart\.js\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /chart(?:\.min)?\.js[^]*?v?([\d]+\.[\d]+\.[\d]+)/i
      ],
      filePatterns: [/chart[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2020-36049', severity: 'medium',
          title: 'Prototype Pollution via options merging',
          affected: ['2.0.0', '2.9.3'], fixed: '2.9.4',
          description: 'Chart.js options deep merge is vulnerable to prototype pollution.',
          exploit: 'new Chart(ctx, {options: JSON.parse(\'{"__proto__":{"polluted":true}}\')})',
          mitigation: 'Upgrade to Chart.js >= 2.9.4.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-36049']
        }
      ]
    },

    // ── YUI ──
    {
      name: 'YUI', icon: '',
      signatures: [
        /YUI\s+v?([\d]+\.[\d]+\.[\d]+)/i,
        /YUI\.version\s*=\s*['"]([\d]+\.[\d]+\.[\d]+)['"]/i
      ],
      filePatterns: [/yui[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i],
      vulnerabilities: [
        {
          id: 'CVE-2013-4942', severity: 'medium',
          title: 'XSS in Flash components',
          affected: ['3.0.0', '3.17.2'], fixed: null,
          description: 'YUI is end-of-life since 2014. Multiple XSS vulnerabilities exist in Flash components.',
          exploit: 'Via SWF files bundled with YUI',
          mitigation: 'Migrate away from YUI. It is no longer maintained.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2013-4942']
        }
      ]
    }
  ];

  // ─── SEMVER COMPARISON HELPERS ───
  function parseVersion(vStr) {
    if (!vStr) return null;
    const parts = vStr.split('.').map(Number);
    return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
  }

  function compareVersions(a, b) {
    if (a.major !== b.major) return a.major < b.major ? -1 : 1;
    if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
    if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
    return 0;
  }

  function isInRange(version, min, max) {
    const v = parseVersion(version);
    const lo = parseVersion(min);
    const hi = parseVersion(max);
    if (!v) return false;
    if (lo && compareVersions(v, lo) < 0) return false;
    if (hi && compareVersions(v, hi) > 0) return false;
    return true;
  }

  // ─── FILENAME / URL BASED DETECTION ───
  JSA.scanFromFilename = function (fileName) {
    const results = [];
    for (const lib of VULN_DB) {
      if (!lib.filePatterns && !lib.cdnPatterns) continue;
      const patterns = [...(lib.filePatterns || []), ...(lib.cdnPatterns || [])];
      for (const pat of patterns) {
        const m = pat.exec(fileName);
        if (m && m[1]) {
          results.push({ name: lib.name, version: m[1], source: 'filename' });
          break;
        }
      }
    }
    return results;
  };

  // ─── SHA-256 HASH FINGERPRINTING ───
  JSA.scanFromHash = async function (content) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      const hashBase64 = 'sha256-' + btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

      const results = [];
      for (const lib of VULN_DB) {
        if (!lib.hashes) continue;
        const version = lib.hashes[hashBase64] || lib.hashes[hashHex];
        if (version) {
          results.push({ name: lib.name, version, source: 'hash' });
        }
      }
      return results;
    } catch (e) {
      console.warn('Hash fingerprinting unavailable:', e);
      return [];
    }
  };

  // ─── MAIN SCAN FUNCTION ───
  JSA.scanVulnerableDependencies = function (content, sourceFile) {
    const findings = [];
    const detected = [];

    function processLib(lib, detectedVersion, sourceFile, confidence, detectionNote) {
      const dedupKey = lib.name + '@' + detectedVersion;
      if (detected.includes(dedupKey)) return;
      detected.push(dedupKey);

      const suffix = detectionNote ? ` (${detectionNote})` : '';
      let hasVuln = false;

      for (const vuln of lib.vulnerabilities) {
        if (isInRange(detectedVersion, vuln.affected[0], vuln.affected[1])) {
          hasVuln = true;
          const nvdUrl = vuln.id.startsWith('CVE-')
            ? `https://nvd.nist.gov/vuln/detail/${vuln.id}`
            : null;

          const finding = {
            value: `${lib.name} v${detectedVersion} — ${vuln.id}${suffix}`,
            type: 'Vulnerable Library',
            sourceFile: sourceFile,
            severity: vuln.severity,
            confidence: confidence,
            ruleId: 'vuln-scanner',
            isBase64: false,
            cveId: vuln.id,
            nvdUrl: nvdUrl,
            libraryName: lib.name,
            detectedVersion: detectedVersion,
            fixedVersion: vuln.fixed,
            isEOL: vuln.fixed === null,
            references: vuln.references || [],
            exploitInfo: {
              risk: vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1),
              description: `${vuln.title}\n\nDetected: ${lib.name} v${detectedVersion}${suffix}\nAffected range: ${vuln.affected[0]} — ${vuln.affected[1]}${vuln.fixed ? '\nFixed in: v' + vuln.fixed : ' (no fix — EOL)'}`,
              exploit: vuln.exploit,
              mitigation: vuln.mitigation
            }
          };

          // Push to BOTH libraries and vulnerabilities tabs
          findings.push(Object.assign({}, finding, { category: 'libraries' }));
          findings.push(Object.assign({}, finding, { category: 'vulnerabilities' }));
        }
      }

      // Safe library — libraries tab only
      if (!hasVuln) {
        findings.push({
          value: `${lib.icon} ${lib.name} v${detectedVersion} — No known vulnerabilities${suffix}`,
          type: 'Library (Safe)',
          category: 'libraries',
          sourceFile: sourceFile,
          severity: 'info',
          confidence: confidence,
          ruleId: 'vuln-scanner',
          isBase64: false,
          libraryName: lib.name,
          detectedVersion: detectedVersion
        });
      }
    }

    // 1) Content-based detection (regex signatures)
    for (const lib of VULN_DB) {
      let detectedVersion = null;
      for (const sig of lib.signatures) {
        const regex = new RegExp(sig);
        const m = regex.exec(content);
        if (m && m[1]) {
          detectedVersion = m[1];
          break;
        }
      }
      if (!detectedVersion) continue;
      processLib(lib, detectedVersion, sourceFile, 'high', '');
    }

    // 2) Filename-based detection (for items not already detected by content)
    const fileDetections = JSA.scanFromFilename(sourceFile);
    for (const fd of fileDetections) {
      const lib = VULN_DB.find(l => l.name === fd.name);
      if (!lib) continue;
      processLib(lib, fd.version, sourceFile, 'medium', 'detected via filename');
    }

    return findings;
  };

  // Expose DB
  JSA.VULN_DB = VULN_DB;

})();
