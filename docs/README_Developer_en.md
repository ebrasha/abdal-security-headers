# 🛡️ Abdal Security Headers

<div align="center">
  <img src="../abdal-security-headers.png" alt="Abdal Security Headers Plugin Screenshot">
</div>

[Persian Developer Guide](README_Developer_fa.md) | [English User Guide](../README.md) | [Persian User Guide](../README_fa.md)

## 📝 Description
Abdal Security Headers is a WordPress plugin that enhances your website's security by implementing and managing HTTP security headers. This plugin provides a simple interface for configuring security headers and Content Security Policy (CSP) directives.

## ✨ Features
### Security Headers Management
- 🔒 X-XSS-Protection header to prevent cross-site scripting attacks
- 🛡️ X-Frame-Options header to prevent clickjacking
- 🔐 X-Content-Type-Options header to prevent MIME-type sniffing
- 🌐 Strict-Transport-Security (HSTS) header to enforce HTTPS connections
- 🚫 Referrer-Policy header to control information leakage
- 🛑 Content Security Policy (CSP) with real-time preview and configuration

### Content Security Policy Features
- 📝 Visual CSP directive editor
- 👁️ Real-time CSP header preview
- 🎨 CSP directive syntax highlighting
- ✅ CSP syntax validation
- 📊 CSP violation reporting configuration

### WordPress Security Enhancements
- 🎭 Hide WordPress version information
- ⚡ Remove unnecessary headers
- 🔌 XML-RPC protection
- 🔑 REST API access control
- 📢 Hide server information

### User Interface
- 💫 Modern UI with iOS-style switches
- 🎛️ Accordion sections for better organization
- 🌐 Full RTL support for multilingual sites
- 💡 Helpful tooltips and documentation
- 🎯 User-friendly settings panel

### Additional Features
- 📱 Mobile-responsive admin interface
- 🔄 Settings import/export capability
- 📝 Security event logging
- ⚙️ Fine-grained control over each security feature
- 🛠️ Developer-friendly hooks and filters

## 🚀 Installation
1. Upload plugin files to `/wp-content/plugins/abdal-security-headers`
2. Activate the plugin through WordPress plugins screen
3. Use `Settings -> Security Headers` to configure the plugin

## ⚙️ Configuration
1. Go to `Settings -> Security Headers` in WordPress admin panel
2. Enable/disable security headers using the switches
3. Configure CSP directives if needed
4. Save settings

## 🔧 Requirements
- WordPress 5.0 or higher
- PHP 7.2 or higher
- Modern web browser for admin interface

## 🐛 Issue Reporting
If you encounter any issues or need configuration help, please contact us at Prof.Shafiei@Gmail.com. You can also report issues on GitLab or GitHub.

## ❤️ Support
If you found this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://alphajet.ir/abdal-donation)

## 🤵 Developer
Made with love by **Ebrahim Shafiei (EbraSha)**
- **Email**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## 📜 License
This project is licensed under GPLv2 or later - see the LICENSE file for details.

## Table of Contents
- [Introduction](#introduction)
- [Installation & Setup](#installation--setup)
- [Project Structure](#project-structure)
- [Key APIs and Functions](#key-apis-and-functions)
- [Contribution Guide](#contribution-guide)
- [Troubleshooting](#troubleshooting)

## Introduction
The Abdal Security Headers plugin is a security enhancement tool for WordPress that provides management of security headers and additional security features.

## Installation & Setup
1. Clone the repository:
```bash
git clone https://github.com/ebrasha/abdal-security-headers.git
```

2. Install dependencies:
```bash
composer install
```

3. Copy files to WordPress plugins folder

## Project Structure
```
abdal-security-headers/
├── docs/                    # Documentation
├── includes/               # Core classes
│   ├── class-ash-admin.php  # Admin panel management
│   └── class-ash-headers.php # Headers implementation
├── languages/              # Translation files
├── assets/                # CSS and JS files
└── abdal-security-headers.php # Main plugin file
```

## Key APIs and Functions

### ASH_Headers Class
Responsible for managing security headers and security features:

```php
// Set security headers
public function set_security_headers()

// Disable XML-RPC
public function ash_block_xmlrpc_access()

// Restrict REST API
public function ash_disable_rest_api()
```

### ASH_Admin Class
Manages admin panel interface:

```php
// Create settings page
public function create_admin_page()

// Register settings
public function page_init()
```

## Contribution Guide
1. Create a new branch for feature or bug fix
2. Make your changes
3. Run tests
4. Create Pull Request

## Troubleshooting
- Enable WP_DEBUG in wp-config.php
- Check error logs
- Use security headers checking tools like SecurityHeaders.com

For more information, visit the [complete documentation](https://github.com/ebrasha/abdal-security-headers/wiki).
