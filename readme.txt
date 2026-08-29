=== Abdal Security Headers ===
Contributors: profshafiei
Donate link: https://ebrasha.com/abdal-donation
Tags: security, security-headers, x-frame-options, content-security-policy, hsts
Requires at least: 6.7.2
Tested up to: 7.1
Stable tag: 5.3.0
Requires PHP: 7.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Enhance WordPress security with HTTP security headers and a Smart CSP Assistant that discovers real site resources for review.

== Description ==

Abdal Security Headers applies HTTP security headers from one dashboard. The Smart CSP Assistant watches what the site actually loads, then suggests CSP origins for you to review. Nothing is auto-whitelisted.

**Smart CSP Assistant:**

* Hybrid discovery: WordPress-registered assets, CSP Report-Only, and a runtime observer
* Timed learning (15 minutes to 24 hours) or manual stop, with optional continuous monitoring
* Merge selected origins into existing CSP fields without replacing current values
* Marks findings already present in CSP fields as Added
* Dangerous values require explicit confirmation
* Blocking CSP is paused during learning so the site keeps working

**Also included:**

* XSS, clickjacking, MIME sniffing, HSTS, Referrer-Policy, and Permissions-Policy
* Live CSP header preview and a full-size CSP directive editor
* WordPress hardening: hide version, strip extra headers, XML-RPC, REST API, generic login errors
* Top-level Security Headers menu, RTL, and mobile layout

**Security Headers Managed:**

* X-Frame-Options
* X-XSS-Protection
* X-Content-Type-Options
* Strict-Transport-Security (HSTS)
* Content-Security-Policy (CSP)
* Referrer-Policy
* Permissions-Policy
* Access-Control-Allow-Origin

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/abdal-security-headers`
2. Activate the plugin through the WordPress plugins screen
3. Open Security Headers in the WordPress admin menu to configure

== Frequently Asked Questions ==

= Does the Smart CSP Assistant auto-whitelist origins? =

No. It only suggests detections. You review them and apply selected sources. Existing CSP values are merged, not replaced.

= Will learning mode break the site? =

During learning, blocking CSP is paused and Report-Only is sent so resources can be discovered without blocking the page.

= Is this plugin compatible with caching plugins? =

Yes, it works with major caching plugins.

= Do I need to write CSP by hand? =

No. Start a Smart Scan, browse the site, then apply the sources you accept. You can still edit directives manually.

== Screenshots ==

1. Dashboard with Security Headers and Additional Security Features
2. Smart CSP Assistant
3. Content Security Policy
4. securityheaders.com score before and after enabling the plugin

== Changelog ==


= 5.3.0 =
* Add complete translations for Spanish, Japanese, German, French, Brazilian Portuguese, Russian, Italian, Turkish, Simplified Chinese, and Arabic

= 5.2.5 =
* Show a programmer credit line at the bottom of the settings dashboard

= 5.2.4 =
* Make the Smart CSP Assistant learning duration segmented control narrower with smaller labels

= 5.2.3 =
* Replace the Smart CSP Assistant learning duration dropdown with a compact segmented control

= 5.2.2 =
* Mark Smart CSP Assistant findings that already exist in CSP directive fields as Added (green, bold)

= 5.2.1 =
* Show a loading spinner on Smart CSP Assistant buttons while requests are in progress

= 5.2.0 =
* Add Smart CSP Assistant with hybrid static, report-only, and runtime discovery
* Suggest CSP origins for review without automatically trusting or whitelisting them

= 5.1.10 =
* Use the WordPress Modal component for save and reset confirmations

= 5.1.9 =
* Move the plugin to a top-level admin menu with a shield icon

= 5.1.8 =
* Open a large editor modal when clicking CSP directive text fields

= 5.1.7 =
* Stack CSP General settings above CSP Directives in matching full-width boxes

= 5.1.6 =
* Use the full WordPress admin content width for the settings dashboard instead of a 1280px container

= 5.1.5 =
* Load admin CSS/JS from the exact options page hook returned by WordPress
* Keep filemtime cache-busting query args on admin assets when hiding the WordPress version
* Do not send the frontend Content-Security-Policy header on wp-admin requests
* Update translation catalogs for the redesigned settings dashboard

= 5.1.3 =
* Fixed CSP preview formatting issues
* Resolved RTL/LTR conflicts in the interface
* Fixed header removal functionality
* Improved compatibility with various WordPress themes


= 5.1.2 =
* Fixed UI/UX issues

= 5.1.1 =
* Fixed UI/UX issues
* Improved mobile responsiveness
* Enhanced RTL support

= 5.1.0 =
* Complete UI/UX redesign
* Added real-time CSP preview
* Added iOS-style switches
* Added full RTL support
* Improved performance
* Updated security headers implementation

= 2.0.0 =
* Updated security headers implementation
* Enhanced documentation

= 1.2.0 =
* Fixed Content-Security-Policy issue
* Removed widget functionality

= 1.1.0 =
* Fixed OOP implementation
* Added widget support

= 1.0 =
* Initial release
* Basic security headers implementation

== Upgrade Notice ==

 
= 5.3.0 =
Adds complete translations for ten additional languages, including Arabic RTL.

= 5.2.5 =
Adds a programmer credit line at the bottom of the Security Headers settings page.

= 5.2.4 =
Makes the learning duration segmented control more compact without changing its height.

= 5.2.3 =
Replaces the learning duration dropdown in Smart CSP Assistant with a compact segmented control.

= 5.2.2 =
Shows Added in the Smart CSP Assistant status column when a discovered origin is already present in the CSP fields.

= 5.2.1 =
Shows a spinner on Smart CSP Assistant actions so longer requests are visibly in progress.

= 5.2.0 =
Adds Smart CSP Assistant so you can discover site resources and review CSP suggestions before merging them.

= 5.1.10 =
Uses the native WordPress Modal for Save Changes and Reset confirmations.

= 5.1.9 =
Adds a top-level Security Headers admin menu with a shield icon instead of nesting the page under Settings.

= 5.1.8 =
Lets you edit long CSP directive values in a full-size modal with OK and Cancel actions.

= 5.1.7 =
Puts CSP General settings and CSP Directives in stacked full-width boxes on the settings dashboard.

= 5.1.6 =
Lets the settings dashboard fill the available WordPress admin content area on wide screens.

= 5.1.5 =
Fixes admin dashboard asset loading so styles and scripts keep their version query args, and prevents frontend CSP from applying inside wp-admin.

= 5.1.3 =
Critical update: Fixes important CSP preview formatting and header removal issues. Resolves RTL/LTR interface conflicts and improves WordPress theme compatibility. All users should upgrade immediately for better functionality and stability.


= 5.1.2 =
This version includes important UI fixes and improved mobile support. Update recommended for all users.

= 5.1.1 =
This version includes important UI fixes and improved mobile support. Update recommended for all users.

= 5.1.0 =
Major update with new interface and enhanced security features. Backup your settings before updating.

== Languages ==
This plugin is available in the following languages:
- English (en_US)
- Persian (fa_IR)
- Spanish (es_ES)
- Japanese (ja)
- German (de_DE)
- French (fr_FR)
- Portuguese - Brazil (pt_BR)
- Russian (ru_RU)
- Italian (it_IT)
- Turkish (tr_TR)
- Chinese Simplified (zh_CN)
- Arabic (ar)

== License ==
This plugin is released under the **GPLv2 or later** License.
License details: [http://www.gnu.org/licenses/gpl-2.0.html](http://www.gnu.org/licenses/gpl-2.0.html)