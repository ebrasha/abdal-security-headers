# 🛡️ Abdal Security Headers

<div align="center">
  <img src="abdal-security-headers.png" alt="Abdal Security Headers">
</div>

[راهنمای فارسی](README_fa.md) · [English Developer Guide](docs/README_Developer_en.md) · [راهنمای توسعه‌دهنده](docs/README_Developer_fa.md)

## 🎯 Why it exists

Writing a working Content Security Policy by hand is slow and easy to get wrong. This plugin applies HTTP security headers from one dashboard, and uses a **Smart CSP Assistant** to discover what the site actually loads so you can tighten CSP without guessing.

## 🧠 Smart CSP Assistant

The assistant **observes** the site. It does **not** auto-whitelist anything.

- 🔎 **Hybrid discovery:** WordPress-registered scripts/styles, CSP Report-Only, and a runtime observer
- ⏱️ **Learning window:** 15 minutes, 1 hour, 6 hours, 24 hours, or manual stop
- 📡 Optional continuous monitoring after learning ends
- 🧩 Suggests origins per directive (`script-src`, `style-src`, `img-src`, …)
- 🏷️ Confidence labels (trusted, likely safe, unknown, risky)
- ✅ You review, then merge selected sources into existing CSP fields — current values are never replaced
- 🟢 If a finding is already in a CSP field, status shows **Added**
- ⚠️ Dangerous tokens (`*`, `unsafe-inline`, `unsafe-eval`, …) need explicit confirmation
- 🛡️ While learning, blocking CSP is paused and Report-Only is sent so the site keeps working

## ✨ Capabilities

- 🔒 XSS, clickjacking, MIME sniffing, HSTS, Referrer-Policy, Permissions-Policy
- 🧱 Full CSP directive editor with a large modal and live header preview
- 🛡️ WordPress hardening: hide version, strip `X-Powered-By` / pingback, XML-RPC, REST API, generic login errors
- 🎛️ Top-level **Security Headers** menu, iOS-style switches, RTL, mobile layout

## 🚀 How to use

1. Install and activate the plugin.
2. Open **Security Headers** in the WordPress admin menu.
3. Turn on the headers you need and enable Content Security Policy.
4. Start a Smart Scan, browse the site, then review detections and apply selected sources.
5. Save changes.

## 🌐 Languages

The plugin is fully translated into:

- 🇺🇸 English (`en_US`)
- 🇮🇷 Persian (`fa_IR`)
- 🇪🇸 Spanish (`es_ES`)
- 🇯🇵 Japanese (`ja`)
- 🇩🇪 German (`de_DE`)
- 🇫🇷 French (`fr_FR`)
- 🇧🇷 Portuguese — Brazil (`pt_BR`)
- 🇷🇺 Russian (`ru_RU`)
- 🇮🇹 Italian (`it_IT`)
- 🇹🇷 Turkish (`tr_TR`)
- 🇨🇳 Chinese Simplified (`zh_CN`)
- 🇸🇦 Arabic (`ar`)

## 🐛 Reporting Issues

If you encounter any issues or have configuration problems, please reach out via email at Prof.Shafiei@Gmail.com. You can also report issues on GitLab or GitHub.

## ❤️ Donation

If you find this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://t.me/AbdalDonationBot)

## 🤵 Programmer

Handcrafted with Passion by **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)
 

 ## License

This project is licensed under the **GNU AGPLv3** with additional terms
as permitted by Section 7 of the AGPLv3. See [LICENSE](./LICENSE) for the
complete text including additional terms.

### Summary of Your Rights and Obligations

- ✅ You **may** use, study, modify, and redistribute this software under
  the terms of AGPLv3.
- ✅ You **may** create derivative works, provided you comply with the
  attribution and renaming requirements below.
- ⚠️ **Network use** triggers source disclosure obligations (AGPLv3 §13).
  If you run a modified version of this software as a network service,
  you must offer the modified source code to its users.
- ⚠️ The names **"Abdal Security Headers"**, **"Abdal"**, **"EbraSha"**, **"Abdal Security Group"**, **"Nahaanbin CyberSecurity Company"** and associated logos are **trademarks** of
  Ebrahim Shafiei (EbraSha) and are **NOT** covered by the AGPLv3 license.
- ⚠️ Forks and modified versions **MUST be renamed** to a name that is
  not confusingly similar to the Project Brand, and may NOT reuse the
  original branding, logos, or visual identity.
- ⚠️ **All author attributions, copyright notices, "About" screens,
  credit lines, and identifying information MUST be preserved** in any
  modified version. Removal or obfuscation is a material violation of
  the License.
- ⚠️ Modified versions must clearly indicate they are modified and must
  not be represented as the official version.

For details, see the **Additional Terms** section in the [LICENSE](./LICENSE) file.

### Commercial / Trademark Licensing

For commercial licensing, trademark licensing, or permissions beyond
the scope of AGPLv3, please contact:

- **Author:** Ebrahim Shafiei (EbraSha)
- **Team:** Abdal Security Group
- **Company:** Nahaanbin CyberSecurity Company
- **Email:** Prof.Shafiei@Gmail.com
- **Repository:** https://github.com/ebrasha/abdal-security-headers

### Reporting License Violations

If you discover a fork, distribution, or commercial use that violates
these terms (such as removed attribution, reused branding, or unauthorized
trademark use), please report it via the contact above.