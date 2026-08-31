/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : admin.js
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2024-03-19 12:00:00
 * Description : Vanilla JavaScript interactions for the security headers dashboard
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

(function () {
    "use strict";

    var config = window.ashAdmin || {};
    var strings = config.strings || {};
    var headerFields = config.headerFields || [];
    var featureFields = config.featureFields || [];

    function ready(callback) {
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", callback);
        } else {
            callback();
        }
    }

    function qs(selector, root) {
        return (root || document).querySelector(selector);
    }

    function qsa(selector, root) {
        return Array.prototype.slice.call((root || document).querySelectorAll(selector));
    }

    function formatString(template, first, second) {
        return String(template || "")
            .replace("%1$d", String(first))
            .replace("%2$d", String(second));
    }

    function createFallbackModal() {
        return {
            confirm: function (title, message) {
                var text = [title, message].filter(Boolean).join("\n\n");
                return Promise.resolve(window.confirm(text));
            },
            alert: function (title, message) {
                window.alert([title, message].filter(Boolean).join("\n\n"));
                return Promise.resolve(true);
            }
        };
    }

    /**
     * Confirm/alert dialogs use the same custom ash-modal as Smart CSP Assistant.
     */
    function createModal() {
        var modal = qs("#ash-confirm-modal");
        var titleEl = qs("#ash-confirm-modal-title");
        var bodyEl = qs("#ash-confirm-modal-body");
        var cancelBtn = qs("[data-ash-confirm-cancel]");
        var okBtn = qs("[data-ash-confirm-ok]");
        var backdrop = qs("[data-ash-confirm-dismiss]");

        if (!modal || !titleEl || !bodyEl || !cancelBtn || !okBtn) {
            return createFallbackModal();
        }

        var pending = null;

        function finish(result) {
            if (!pending) {
                return;
            }
            var resolve = pending;
            pending = null;
            modal.hidden = true;
            document.body.classList.remove("ash-modal-open");
            resolve(!!result);
        }

        function open(options) {
            return new Promise(function (resolve) {
                if (pending) {
                    pending(false);
                    pending = null;
                }
                pending = resolve;
                titleEl.textContent = options.title || "";
                bodyEl.textContent = "";
                if (options.message) {
                    var paragraph = document.createElement("p");
                    paragraph.textContent = options.message;
                    bodyEl.appendChild(paragraph);
                }
                cancelBtn.hidden = !!options.alert;
                okBtn.textContent = options.confirmText || strings.yes || "Yes";
                modal.hidden = false;
                document.body.classList.add("ash-modal-open");
            });
        }

        cancelBtn.addEventListener("click", function () {
            finish(false);
        });
        backdrop.addEventListener("click", function () {
            finish(false);
        });
        okBtn.addEventListener("click", function () {
            finish(true);
        });
        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape" && modal && !modal.hidden) {
                finish(false);
            }
        });

        return {
            confirm: function (title, message) {
                return open({
                    title: title,
                    message: message,
                    confirmText: strings.yes,
                    alert: false
                });
            },
            alert: function (title, message) {
                return open({
                    title: title,
                    message: message,
                    confirmText: strings.ok,
                    alert: true
                });
            }
        };
    }

    function countChecked(ids) {
        return ids.filter(function (id) {
            var field = document.getElementById(id);
            return field && field.checked;
        }).length;
    }

    function updateSummaries() {
        var headerTotal = headerFields.length;
        var featureTotal = featureFields.length;
        var headerActive = countChecked(headerFields);
        var featureActive = countChecked(featureFields);
        var total = headerTotal + featureTotal;
        var active = headerActive + featureActive;
        var ratio = total > 0 ? active / total : 0;

        var statusCard = qs('[data-ash-summary="status"]');
        var headersCard = qs('[data-ash-summary="headers"]');
        var featuresCard = qs('[data-ash-summary="features"]');
        var cspCard = qs('[data-ash-summary="csp"]');
        var cspToggle = document.getElementById("content_security_policy");
        var cspEnabled = !!(cspToggle && cspToggle.checked);

        if (statusCard) {
            var tone = "muted";
            var label = strings.statusNeedsAttention;
            var hint = strings.statusNeedsHint;
            if (ratio >= 0.75) {
                tone = "green";
                label = strings.statusGood;
                hint = strings.statusGoodHint;
            } else if (ratio >= 0.4) {
                tone = "warning";
                label = strings.statusFair;
                hint = strings.statusFairHint;
            }
            statusCard.className = "ash-summary-card ash-summary-card--" + tone;
            qs("[data-ash-summary-value]", statusCard).textContent = label;
            qs("[data-ash-summary-hint]", statusCard).textContent = hint;
        }

        if (headersCard) {
            qs("[data-ash-summary-value]", headersCard).textContent = headerActive + " / " + headerTotal;
            qs("[data-ash-summary-hint]", headersCard).textContent = formatString(strings.headersHint, headerActive, headerTotal);
        }

        if (featuresCard) {
            qs("[data-ash-summary-value]", featuresCard).textContent = featureActive + " / " + featureTotal;
            qs("[data-ash-summary-hint]", featuresCard).textContent = formatString(strings.featuresHint, featureActive, featureTotal);
        }

        if (cspCard) {
            cspCard.className = "ash-summary-card " + (cspEnabled ? "ash-summary-card--green" : "ash-summary-card--muted");
            qs("[data-ash-summary-value]", cspCard).textContent = cspEnabled ? strings.cspOn : strings.cspOff;
            qs("[data-ash-summary-hint]", cspCard).textContent = cspEnabled ? strings.cspOnHint : strings.cspOffHint;
        }
    }

    function updateCspPreview(form) {
        var preview = qs("#csp-preview-content");
        var cspToggle = document.getElementById("content_security_policy");
        if (!preview) {
            return;
        }

        var directives = [];
        qsa("input[data-csp-directive]").forEach(function (input) {
            var directive = (input.getAttribute("data-csp-directive") || "").replace(/_/g, "-");
            var value = (input.value || "").trim();
            if (directive && value) {
                directives.push(directive + " " + value);
            }
        });

        var headerValue = "";
        if (directives.length > 0) {
            headerValue = "Content-Security-Policy: " + directives.join("; ");
        }

        if (cspToggle && !cspToggle.checked) {
            preview.textContent = headerValue ? headerValue + "\n\n" + (strings.cspDisabled || "") : (strings.cspDisabled || "");
            preview.setAttribute("data-ash-copy-text", headerValue);
        } else if (!headerValue) {
            preview.textContent = strings.cspEmpty || "";
            preview.setAttribute("data-ash-copy-text", "");
        } else {
            preview.textContent = headerValue;
            preview.setAttribute("data-ash-copy-text", headerValue);
        }

        if (form) {
            form.classList.toggle("is-csp-off", !(cspToggle && cspToggle.checked));
        }
    }

    function copyPreview() {
        var preview = qs("#csp-preview-content");
        var button = qs("[data-ash-copy]");
        if (!preview || !button) {
            return Promise.resolve(false);
        }

        var text = (preview.getAttribute("data-ash-copy-text") || preview.textContent || "").trim();
        if (!text) {
            return Promise.resolve(false);
        }

        var done = function () {
            button.classList.add("is-copied");
            button.setAttribute("aria-label", strings.copied || "Copied");
            button.title = strings.copied || "Copied";
            window.setTimeout(function () {
                button.classList.remove("is-copied");
                button.setAttribute("aria-label", strings.copyCsp || "Copy");
                button.title = strings.copyCsp || "Copy";
            }, 1600);
            return true;
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text).then(done).catch(function () {
                return false;
            });
        }

        var area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        var ok = false;
        try {
            ok = document.execCommand("copy");
        } catch (error) {
            ok = false;
        }
        document.body.removeChild(area);
        return Promise.resolve(ok ? done() : false);
    }

    function commitFormDefaults(form) {
        qsa("input, select, textarea", form).forEach(function (field) {
            if (field.type === "checkbox" || field.type === "radio") {
                field.defaultChecked = field.checked;
                return;
            }
            if (field.tagName === "SELECT") {
                Array.prototype.forEach.call(field.options, function (option) {
                    option.defaultSelected = option.selected;
                });
                return;
            }
            field.defaultValue = field.value;
        });
    }

    function bindHeadersPage(form, modal) {
        if (!form || !form.hasAttribute("data-ash-headers-page")) {
            return {
                sync: function () {},
                afterSave: function () {},
                afterReset: function () {}
            };
        }

        var preloadMinAge = 31536000;
        var xssPolicy = qs("[data-ash-xss-policy]", form);
        var xssReportRow = qs("[data-ash-xss-report-row]", form);
        var hstsPreset = qs("[data-ash-hsts-preset]", form);
        var hstsCustomRow = qs("[data-ash-hsts-custom-row]", form);
        var hstsCustomInput = qs("#ash-hsts-max-age-custom", form);
        var hstsPreload = qs("[data-ash-hsts-preload]", form);
        var hstsSubdomains = qs("[data-ash-hsts-subdomains]", form);
        var lastHstsPresetAge = hstsPreset && hstsPreset.value !== "custom" ? hstsPreset.value : "";
        var referrerPolicy = qs("[data-ash-referrer-policy]", form);
        var referrerWarning = qs("[data-ash-referrer-warning]", form);
        var addButton = qs("[data-ash-pp-add]", form);
        var newNameInput = qs("[data-ash-pp-new-name]", form);
        var customList = qs("[data-ash-pp-custom-list]", form);
        var customTemplate = qs("#ash-pp-custom-template");

        function syncHeaderCards() {
            qsa("[data-ash-header-card]", form).forEach(function (card) {
                var enableId = card.getAttribute("data-ash-enable") || "";
                var toggle = enableId ? document.getElementById(enableId) : null;
                card.classList.toggle("is-disabled", !(toggle && toggle.checked));
            });
        }

        function syncXssReport() {
            if (!xssReportRow) {
                return;
            }
            xssReportRow.hidden = !(xssPolicy && xssPolicy.value === "1_report");
        }

        function syncHstsCustom() {
            if (!hstsCustomRow) {
                return;
            }
            hstsCustomRow.hidden = !(hstsPreset && hstsPreset.value === "custom");
        }

        function currentHstsMaxAge() {
            if (!hstsPreset) {
                return preloadMinAge;
            }
            if (hstsPreset.value === "custom") {
                var customAge = parseInt(hstsCustomInput ? hstsCustomInput.value : "0", 10);
                return isNaN(customAge) ? 0 : customAge;
            }
            var presetAge = parseInt(hstsPreset.value, 10);
            return isNaN(presetAge) ? 0 : presetAge;
        }

        function setHstsMaxAge(seconds) {
            if (!hstsPreset) {
                return;
            }
            var asString = String(seconds);
            var hasPreset = false;
            Array.prototype.forEach.call(hstsPreset.options, function (option) {
                if (option.value === asString) {
                    hasPreset = true;
                }
            });
            if (hasPreset) {
                hstsPreset.value = asString;
            } else {
                hstsPreset.value = "custom";
                if (hstsCustomInput) {
                    hstsCustomInput.value = asString;
                }
            }
            syncHstsCustom();
        }

        function applyHstsConstraints(source) {
            if (!hstsPreload || !hstsPreload.checked) {
                return;
            }
            if (hstsSubdomains && !hstsSubdomains.checked) {
                hstsSubdomains.checked = true;
            }
            if (currentHstsMaxAge() < preloadMinAge) {
                if (source === "age") {
                    hstsPreload.checked = false;
                } else {
                    setHstsMaxAge(preloadMinAge);
                }
            }
        }

        function syncReferrerWarning() {
            if (!referrerWarning) {
                return;
            }
            referrerWarning.hidden = !(referrerPolicy && referrerPolicy.value === "unsafe-url");
        }

        function syncPpOrigins(select) {
            if (!select) {
                return;
            }
            var item = select.closest("[data-ash-pp-item]");
            if (!item) {
                return;
            }
            var originsRow = qs("[data-ash-pp-origins-row]", item);
            if (originsRow) {
                originsRow.hidden = select.value !== "custom";
            }
        }

        function syncAllPpOrigins() {
            qsa("[data-ash-pp-policy]", form).forEach(syncPpOrigins);
        }

        function directiveNameTaken(name, exceptItem) {
            return qsa("[data-ash-pp-item]", form).some(function (item) {
                if (exceptItem && item === exceptItem) {
                    return false;
                }
                return (item.getAttribute("data-ash-pp-name") || "").toLowerCase() === name;
            });
        }

        function nextCustomIndex() {
            var max = -1;
            if (!customList) {
                return 0;
            }
            qsa("[name]", customList).forEach(function (field) {
                var match = String(field.getAttribute("name") || "").match(/^ash_options\[pp_custom\]\[(\d+)\]/);
                if (match) {
                    max = Math.max(max, parseInt(match[1], 10));
                }
            });
            return max + 1;
        }

        function replaceIndexToken(root, index) {
            var token = "__INDEX__";
            var value = String(index);
            qsa("[id], [name], [for]", root).forEach(function (field) {
                ["id", "name", "for"].forEach(function (attr) {
                    var current = field.getAttribute(attr);
                    if (current && current.indexOf(token) !== -1) {
                        field.setAttribute(attr, current.split(token).join(value));
                    }
                });
            });
        }

        function addCustomDirective() {
            if (!customList || !customTemplate || !customTemplate.content) {
                return;
            }
            var name = ((newNameInput && newNameInput.value) || "").trim().toLowerCase();
            if (!/^[a-z][a-z0-9-]{1,62}$/.test(name)) {
                modal.alert(strings.error || "", strings.invalidDirectiveName || "");
                return;
            }
            if (directiveNameTaken(name)) {
                modal.alert(strings.error || "", strings.duplicateDirectiveName || "");
                return;
            }

            var fragment = customTemplate.content.cloneNode(true);
            var index = nextCustomIndex();
            replaceIndexToken(fragment, index);
            var item = qs("[data-ash-pp-item]", fragment);
            if (!item) {
                return;
            }
            item.setAttribute("data-ash-pp-name", name);
            var nameField = qs("[data-ash-pp-name-input]", item);
            if (nameField) {
                nameField.value = name;
            }
            customList.appendChild(fragment);
            if (newNameInput) {
                newNameInput.value = "";
            }
        }

        function syncAll() {
            syncHeaderCards();
            syncXssReport();
            syncHstsCustom();
            syncReferrerWarning();
            syncAllPpOrigins();
        }

        form.addEventListener("change", function (event) {
            var target = event.target;
            if (!target) {
                return;
            }
            if (target.hasAttribute("data-ash-header-enable")) {
                syncHeaderCards();
            }
            if (target.hasAttribute("data-ash-xss-policy")) {
                syncXssReport();
            }
            if (target.hasAttribute("data-ash-hsts-preset")) {
                if (hstsPreset.value === "custom") {
                    if (hstsCustomInput && lastHstsPresetAge) {
                        hstsCustomInput.value = lastHstsPresetAge;
                    }
                } else {
                    lastHstsPresetAge = hstsPreset.value;
                }
                syncHstsCustom();
                applyHstsConstraints("age");
            }
            if (target.hasAttribute("data-ash-hsts-preload")) {
                applyHstsConstraints("preload");
            }
            if (target.hasAttribute("data-ash-hsts-subdomains") && hstsPreload && hstsPreload.checked && hstsSubdomains && !hstsSubdomains.checked) {
                hstsSubdomains.checked = true;
            }
            if (target.hasAttribute("data-ash-referrer-policy")) {
                syncReferrerWarning();
            }
            if (target.hasAttribute("data-ash-pp-policy")) {
                syncPpOrigins(target);
            }
        });

        form.addEventListener("input", function (event) {
            var target = event.target;
            if (!target) {
                return;
            }
            if (target.id === "ash-hsts-max-age-custom") {
                applyHstsConstraints("age");
            }
            if (target.hasAttribute("data-ash-pp-name-input")) {
                var item = target.closest("[data-ash-pp-item]");
                if (item) {
                    item.setAttribute("data-ash-pp-name", String(target.value || "").trim().toLowerCase());
                }
            }
        });

        if (addButton) {
            addButton.addEventListener("click", addCustomDirective);
        }

        if (newNameInput) {
            newNameInput.addEventListener("keydown", function (event) {
                if (event.key === "Enter") {
                    event.preventDefault();
                    addCustomDirective();
                }
            });
        }

        form.addEventListener("click", function (event) {
            var removeButton = event.target.closest ? event.target.closest("[data-ash-pp-remove]") : null;
            if (!removeButton || !form.contains(removeButton)) {
                return;
            }
            var item = removeButton.closest("[data-ash-pp-item]");
            if (!item) {
                return;
            }
            modal.confirm(strings.removeDirective || "", strings.confirmRemoveDirective || "").then(function (confirmed) {
                if (!confirmed || !item.parentNode) {
                    return;
                }
                item.parentNode.removeChild(item);
            });
        });

        syncAll();

        return {
            sync: syncAll,
            afterSave: function () {
                qsa("[data-ash-pp-custom-new]", form).forEach(function (row) {
                    row.removeAttribute("data-ash-pp-custom-new");
                });
            },
            afterReset: function () {
                qsa("[data-ash-pp-custom-new]", form).forEach(function (row) {
                    if (row.parentNode) {
                        row.parentNode.removeChild(row);
                    }
                });
                syncAll();
            }
        };
    }

    function bindFeaturesPage(form) {
        if (!form || !form.hasAttribute("data-ash-features-page")) {
            return {
                sync: function () {},
                afterReset: function () {}
            };
        }

        function isChecked(id) {
            var el = document.getElementById(id);
            return !!(el && el.checked);
        }

        function syncFeatureCards() {
            qsa("[data-ash-feature-card]", form).forEach(function (card) {
                var enableId = card.getAttribute("data-ash-enable") || "";
                var toggle = enableId ? document.getElementById(enableId) : null;
                card.classList.toggle("is-disabled", !(toggle && toggle.checked));
            });
        }

        function syncLoginCustom() {
            var mode = qs("[data-ash-login-mode]", form);
            var row = qs("[data-ash-login-custom-row]", form);
            if (!row) {
                return;
            }
            row.hidden = !(mode && mode.value === "custom");
        }

        function syncXmlrpc() {
            var mode = qs("[data-ash-xmlrpc-mode]", form);
            var value = mode ? mode.value : "auth";
            var custom = qs("[data-ash-xmlrpc-custom-panel]", form);
            var warning = qs("[data-ash-xmlrpc-all-warning]", form);
            var badge = qs("[data-ash-xmlrpc-all-badge]", form);
            if (custom) {
                custom.hidden = value !== "custom";
            }
            if (warning) {
                warning.hidden = value !== "all";
            }
            if (badge) {
                badge.hidden = value !== "all";
            }
        }

        function syncPingbackRecommend() {
            var recommend = qs("[data-ash-pingback-recommend]", form);
            if (!recommend) {
                return;
            }
            var mode = qs("[data-ash-xmlrpc-mode]", form);
            var value = mode ? mode.value : "auth";
            var xmlrpcOn = isChecked("disable_xmlrpc");
            var pingbackOn = isChecked("remove_x_pingback");
            recommend.hidden = !(xmlrpcOn && (value === "pingback" || value === "all") && !pingbackOn);
        }

        function syncRest() {
            var policy = qs("[data-ash-rest-policy]", form);
            var value = policy ? policy.value : "authenticated";
            var roles = qs("[data-ash-rest-roles-panel]", form);
            var capRow = qs("[data-ash-rest-cap-row]", form);
            var warning = qs("[data-ash-rest-blockall-warning]", form);
            var badge = qs("[data-ash-rest-blockall-badge]", form);
            if (roles) {
                roles.hidden = value !== "roles";
            }
            if (capRow) {
                capRow.hidden = value !== "capability";
            }
            if (warning) {
                warning.hidden = value !== "block_all";
            }
            if (badge) {
                badge.hidden = value !== "block_all";
            }

            var usersPanel = qs("[data-ash-rest-users-panel]", form);
            if (usersPanel) {
                usersPanel.classList.toggle("is-muted", !isChecked("rest_users_restrict"));
            }

            var usersPolicy = qs("[data-ash-rest-users-policy]", form);
            var usersCap = qs("[data-ash-rest-users-cap-row]", form);
            if (usersCap) {
                usersCap.hidden = !(usersPolicy && usersPolicy.value === "capability");
            }
        }

        function syncAll() {
            syncFeatureCards();
            syncLoginCustom();
            syncXmlrpc();
            syncPingbackRecommend();
            syncRest();
        }

        form.addEventListener("change", function (event) {
            var target = event.target;
            if (!target) {
                return;
            }
            if (
                target.hasAttribute("data-ash-header-enable") ||
                target.hasAttribute("data-ash-login-mode") ||
                target.hasAttribute("data-ash-xmlrpc-mode") ||
                target.hasAttribute("data-ash-pingback-enable") ||
                target.hasAttribute("data-ash-rest-policy") ||
                target.hasAttribute("data-ash-rest-users-policy") ||
                target.hasAttribute("data-ash-users-enable")
            ) {
                syncAll();
            }
        });

        syncAll();

        return {
            sync: syncAll,
            afterReset: syncAll
        };
    }

    function serializeForm(form) {
        var data = new FormData(form);
        if (!data.has("submit")) {
            data.append("submit", "1");
        }
        var params = new URLSearchParams();
        data.forEach(function (value, key) {
            params.append(key, value);
        });
        return params.toString();
    }

    function bindCspEditor(form) {
        var editorModal = qs("#ash-csp-editor-modal");
        if (!editorModal) {
            return;
        }

        var titleEl = qs("#ash-csp-editor-title", editorModal);
        var textarea = qs("#ash-csp-editor-text", editorModal);
        var okBtn = qs("[data-ash-csp-editor-ok]", editorModal);
        var cancelBtn = qs("[data-ash-csp-editor-cancel]", editorModal);
        var backdrop = qs("[data-ash-csp-editor-dismiss]", editorModal);
        var activeInput = null;
        var ignoreFocus = false;

        function setIgnoreFocus() {
            ignoreFocus = true;
            window.setTimeout(function () {
                ignoreFocus = false;
            }, 50);
        }

        function closeEditor(apply) {
            if (editorModal.hidden) {
                return;
            }

            if (apply && activeInput) {
                activeInput.value = textarea.value;
                activeInput.dispatchEvent(new Event("input", { bubbles: true }));
            }

            editorModal.hidden = true;
            document.body.classList.remove("ash-modal-open");
            setIgnoreFocus();
            activeInput = null;
        }

        function openEditor(input) {
            if (!input) {
                return;
            }

            if (!editorModal.hidden && activeInput === input) {
                return;
            }

            activeInput = input;
            var directive = input.getAttribute("data-csp-directive") || "";
            var template = strings.editDirective || "Edit %s";
            titleEl.textContent = template.replace("%s", directive);
            textarea.value = input.value || "";
            textarea.setAttribute("aria-label", directive);
            editorModal.hidden = false;
            document.body.classList.add("ash-modal-open");

            window.setTimeout(function () {
                textarea.focus();
                var length = textarea.value.length;
                try {
                    textarea.setSelectionRange(length, length);
                } catch (error) {
                    // Ignore selection errors in older browsers.
                }
            }, 0);
        }

        qsa("[data-ash-csp-editor]", form).forEach(function (input) {
            input.addEventListener("mousedown", function (event) {
                if (event.button !== 0) {
                    return;
                }
                event.preventDefault();
                openEditor(input);
            });

            input.addEventListener("focus", function () {
                if (ignoreFocus) {
                    return;
                }
                openEditor(input);
            });

            input.addEventListener("keydown", function (event) {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openEditor(input);
                }
            });
        });

        if (okBtn) {
            okBtn.addEventListener("click", function () {
                closeEditor(true);
            });
        }

        if (cancelBtn) {
            cancelBtn.addEventListener("click", function () {
                closeEditor(false);
            });
        }

        if (backdrop) {
            backdrop.addEventListener("click", function () {
                closeEditor(false);
            });
        }

        document.addEventListener("keydown", function (event) {
            if (editorModal.hidden || event.key !== "Escape") {
                return;
            }
            event.preventDefault();
            closeEditor(false);
        });
    }

    function bindHelp() {
        var help = qs("[data-ash-help]");
        if (!help) {
            return;
        }

        var toggle = qs("[data-ash-help-toggle]", help);
        var menu = qs(".ash-help__menu", help);

        toggle.addEventListener("click", function () {
            var isOpen = !menu.hidden;
            menu.hidden = isOpen;
            toggle.setAttribute("aria-expanded", isOpen ? "false" : "true");
        });

        document.addEventListener("click", function (event) {
            if (!help.contains(event.target)) {
                menu.hidden = true;
                toggle.setAttribute("aria-expanded", "false");
            }
        });
    }

    function bindDashboard(modal) {
        var root = qs("[data-ash-dashboard]");
        if (!root) {
            return;
        }

        var cards = qsa("[data-ash-profile-option]", root);

        function selectedProfile() {
            var active = qs("[data-ash-profile-option][aria-checked='true']", root);
            return active ? active.getAttribute("data-ash-profile-option") : "";
        }

        function selectProfile(id) {
            cards.forEach(function (card) {
                var on = card.getAttribute("data-ash-profile-option") === id;
                card.classList.toggle("is-selected", on);
                card.setAttribute("aria-checked", on ? "true" : "false");
            });
        }

        function setBusy(busy) {
            qsa("[data-ash-apply-profile], [data-ash-reset-profile], [data-ash-recalculate]", root).forEach(function (button) {
                button.disabled = !!busy;
                if (button.hasAttribute("data-ash-apply-profile")) {
                    button.classList.toggle("is-busy", !!busy);
                }
            });
        }

        function parseJsonResponse(response) {
            return response.text().then(function (text) {
                var json = null;
                try {
                    json = JSON.parse(text);
                } catch (error) {
                    json = null;
                }
                if (!json || json.success !== true || !json.data) {
                    var message = strings.centerError || strings.errorMessage;
                    if (json && json.data && json.data.message) {
                        message = json.data.message;
                    }
                    throw new Error(message);
                }
                return json.data;
            });
        }

        function postTask(task, profile) {
            var body = new URLSearchParams();
            body.set("action", "ash_security_center");
            body.set("nonce", config.nonce || "");
            body.set("task", task);
            if (profile) {
                body.set("profile", profile);
            }

            return fetch(config.ajaxUrl || window.ajaxurl || "", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                credentials: "same-origin",
                body: body.toString()
            }).then(parseJsonResponse);
        }

        function setMetric(name, value, hint, tone) {
            var card = qs('[data-ash-metric="' + name + '"]', root);
            if (!card) {
                return;
            }
            if (tone) {
                var keep = "";
                if (name === "headers") {
                    keep = "blue";
                } else if (name === "features") {
                    keep = "purple";
                } else {
                    keep = tone;
                }
                card.className = "ash-summary-card ash-summary-card--" + keep;
            }
            var valueEl = qs("[data-ash-metric-value]", card);
            var hintEl = qs("[data-ash-metric-hint]", card);
            if (valueEl) {
                valueEl.textContent = value || "";
            }
            if (hintEl) {
                hintEl.textContent = hint || "";
            }
        }

        function renderAttention(items, emptyText) {
            var list = qs("[data-ash-attention-list]", root);
            if (!list) {
                return;
            }
            list.textContent = "";
            if (!items || !items.length) {
                var empty = document.createElement("p");
                empty.className = "ash-section-help";
                empty.textContent = emptyText || strings.noAttention || "";
                list.appendChild(empty);
                return;
            }
            items.forEach(function (item) {
                var box = document.createElement("div");
                box.className = item && item.tone === "muted" ? "ash-callout" : "ash-callout ash-callout--warning";
                var title = document.createElement("strong");
                title.textContent = item && item.title ? item.title : "";
                var description = document.createElement("span");
                description.textContent = item && item.description ? item.description : "";
                box.appendChild(title);
                box.appendChild(description);
                list.appendChild(box);
            });
        }

        function renderSummary(rows) {
            var list = qs("[data-ash-summary-list]", root);
            if (!list) {
                return;
            }
            list.textContent = "";
            (rows || []).forEach(function (row) {
                var item = document.createElement("div");
                item.className = "ash-toggle-row";
                var info = document.createElement("div");
                info.className = "ash-toggle-row__info";
                var label = document.createElement("span");
                label.className = "ash-toggle-row__label";
                label.textContent = row && row.label ? row.label : "";
                info.appendChild(label);
                var value = document.createElement("span");
                value.className = "ash-metric-value";
                value.textContent = row && row.value ? row.value : "";
                item.appendChild(info);
                item.appendChild(value);
                list.appendChild(item);
            });
        }

        function applyPayload(payload) {
            if (!payload) {
                return;
            }
            var headers = payload.headers || {};
            var features = payload.features || {};
            var csp = payload.csp || {};
            var profile = payload.profile || {};

            setMetric("score", String(payload.score != null ? payload.score : ""), payload.score_hint || "", payload.score_tone || "muted");
            setMetric("headers", headers.label || "", headers.hint || "", "blue");
            setMetric("features", features.label || "", features.hint || "", "purple");
            setMetric("csp", csp.label || "", csp.hint || "", csp.tone || "muted");
            renderAttention(payload.attention || [], payload.attention_empty || "");
            renderSummary(payload.summary || []);

            var statusText = qs("[data-ash-profile-status-text]", root);
            if (statusText) {
                statusText.textContent = profile.status_text || profile.hint || "";
            }
            if (profile.stored) {
                selectProfile(profile.stored);
            }
        }

        cards.forEach(function (card) {
            card.addEventListener("click", function () {
                selectProfile(card.getAttribute("data-ash-profile-option"));
            });
            card.addEventListener("keydown", function (event) {
                if (event.key !== "ArrowRight" && event.key !== "ArrowDown" && event.key !== "ArrowLeft" && event.key !== "ArrowUp") {
                    return;
                }
                event.preventDefault();
                var index = cards.indexOf(card);
                if (index < 0) {
                    return;
                }
                var next = index;
                if (event.key === "ArrowRight" || event.key === "ArrowDown") {
                    next = (index + 1) % cards.length;
                } else {
                    next = (index - 1 + cards.length) % cards.length;
                }
                selectProfile(cards[next].getAttribute("data-ash-profile-option"));
                cards[next].focus();
            });
        });

        function confirmAndRun(title, message, task, profile) {
            modal.confirm(title, message).then(function (confirmed) {
                if (!confirmed) {
                    return;
                }
                setBusy(true);
                postTask(task, profile).then(function (payload) {
                    applyPayload(payload);
                    return modal.alert(strings.success || "", payload.message || "");
                }).catch(function (error) {
                    return modal.alert(strings.error || "", error && error.message ? error.message : strings.centerError);
                }).then(function () {
                    setBusy(false);
                });
            });
        }

        qsa("[data-ash-apply-profile]", root).forEach(function (button) {
            button.addEventListener("click", function () {
                var profile = selectedProfile();
                if (!profile) {
                    modal.alert(strings.error || "", strings.selectProfile || "");
                    return;
                }
                var message = strings.confirmApplyProfile || "";
                if (profile === "hardened") {
                    message = strings.confirmApplyHardened || message;
                } else if (profile === "manual") {
                    message = strings.confirmApplyManual || message;
                }
                confirmAndRun(strings.confirmApplyTitle || strings.saveChanges || "", message, "apply", profile);
            });
        });

        qsa("[data-ash-reset-profile]", root).forEach(function (button) {
            button.addEventListener("click", function () {
                confirmAndRun(
                    strings.resetProfileTitle || strings.reset || "",
                    strings.confirmResetProfile || "",
                    "reset",
                    ""
                );
            });
        });

        qsa("[data-ash-recalculate]", root).forEach(function (button) {
            button.addEventListener("click", function () {
                setBusy(true);
                postTask("recalculate", "").then(function (payload) {
                    applyPayload(payload);
                    return modal.alert(strings.success || "", payload.message || strings.successRecalculate || "");
                }).catch(function (error) {
                    return modal.alert(strings.error || "", error && error.message ? error.message : strings.centerError);
                }).then(function () {
                    setBusy(false);
                });
            });
        });
    }

    function bindSettingsTransfer(modal) {
        var root = qs("[data-ash-settings-transfer]");
        if (!root) {
            return;
        }

        var exportButton = qs("[data-ash-export-settings]", root);
        var importButton = qs("[data-ash-import-settings]", root);
        var chooseButton = qs("[data-ash-choose-file]", root);
        var fileInput = qs("[data-ash-import-file]", root);
        var fileName = qs("[data-ash-import-filename]", root);
        var busy = false;

        function parseJsonResponse(response) {
            return response.text().then(function (text) {
                var json = null;
                try {
                    json = JSON.parse(text);
                } catch (error) {
                    json = null;
                }
                if (!json || json.success !== true || !json.data) {
                    var message = strings.transferError || strings.errorMessage;
                    if (json && json.data && json.data.message) {
                        message = json.data.message;
                    }
                    throw new Error(message);
                }
                return json.data;
            });
        }

        function setBusy(isBusy) {
            busy = !!isBusy;
            [exportButton, importButton, chooseButton].forEach(function (button) {
                if (button) {
                    button.disabled = busy;
                    button.classList.toggle("is-busy", busy && (button === exportButton || button === importButton));
                }
            });
            if (fileInput) {
                fileInput.disabled = busy;
            }
        }

        function safeFilename(name) {
            var cleaned = String(name || "").replace(/[^A-Za-z0-9._-]/g, "");
            if (!cleaned) {
                cleaned = "abdal-security-headers-settings.json";
            }
            if (!/\.json$/i.test(cleaned)) {
                cleaned += ".json";
            }
            return cleaned;
        }

        function downloadPayload(filename, payload) {
            var text = JSON.stringify(payload, null, 2);
            var blob = new Blob([text], { type: "application/json;charset=utf-8" });
            var url = URL.createObjectURL(blob);
            var link = document.createElement("a");
            link.href = url;
            link.download = safeFilename(filename);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }

        function selectedFile() {
            if (!fileInput || !fileInput.files || !fileInput.files.length) {
                return null;
            }
            return fileInput.files[0];
        }

        function updateFileLabel() {
            if (!fileName) {
                return;
            }
            var file = selectedFile();
            fileName.textContent = file && file.name
                ? file.name
                : (strings.noFileSelected || "No file selected");
        }

        if (chooseButton && fileInput) {
            chooseButton.addEventListener("click", function () {
                if (busy) {
                    return;
                }
                fileInput.click();
            });
        }

        if (fileInput) {
            fileInput.addEventListener("change", updateFileLabel);
        }

        if (exportButton) {
            exportButton.addEventListener("click", function () {
                if (busy) {
                    return;
                }

                var body = new URLSearchParams();
                body.set("action", "ash_settings_transfer");
                body.set("nonce", config.settingsNonce || "");
                body.set("task", "export");

                setBusy(true);
                fetch(config.ajaxUrl || window.ajaxurl || "", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                    },
                    credentials: "same-origin",
                    body: body.toString()
                }).then(parseJsonResponse).then(function (data) {
                    if (!data || typeof data.payload !== "object" || data.payload === null) {
                        throw new Error(strings.transferError || strings.errorMessage);
                    }
                    downloadPayload(data.filename, data.payload);
                    return modal.alert(strings.success || "", data.message || strings.successExport || "");
                }).catch(function (error) {
                    return modal.alert(strings.error || "", error && error.message ? error.message : strings.transferError);
                }).then(function () {
                    setBusy(false);
                });
            });
        }

        if (importButton) {
            importButton.addEventListener("click", function () {
                if (busy) {
                    return;
                }

                var file = selectedFile();
                if (!file) {
                    modal.alert(strings.error || "", strings.importNoFile || "");
                    return;
                }

                modal.confirm(
                    strings.confirmImportTitle || "",
                    strings.confirmImport || ""
                ).then(function (confirmed) {
                    if (!confirmed) {
                        return;
                    }

                    var body = new FormData();
                    body.append("action", "ash_settings_transfer");
                    body.append("nonce", config.settingsNonce || "");
                    body.append("task", "import");
                    body.append("file", file);

                    setBusy(true);
                    return fetch(config.ajaxUrl || window.ajaxurl || "", {
                        method: "POST",
                        credentials: "same-origin",
                        body: body
                    }).then(parseJsonResponse).then(function (data) {
                        return modal.alert(strings.success || "", data.message || strings.successImport || "").then(function () {
                            window.location.reload();
                        });
                    }).catch(function (error) {
                        return modal.alert(strings.error || "", error && error.message ? error.message : strings.transferError);
                    }).then(function () {
                        setBusy(false);
                    });
                });
            });
        }
    }

    ready(function () {
        bindHelp();

        var modal = createModal();
        bindDashboard(modal);
        bindSettingsTransfer(modal);

        var form = qs("#ash-settings-form");
        if (!form) {
            return;
        }
        var submitButton = qs("#ash-submit-button", form);
        var resetButton = qs("#ash-reset-button", form);
        var headersPage = bindHeadersPage(form, modal);
        var featuresPage = bindFeaturesPage(form);

        bindCspEditor(form);
        updateSummaries();
        updateCspPreview(form);

        form.addEventListener("change", function () {
            updateSummaries();
            updateCspPreview(form);
        });

        form.addEventListener("input", function (event) {
            if (event.target && event.target.getAttribute("data-csp-directive") !== null) {
                updateCspPreview(form);
            }
        });

        form.addEventListener("submit", function (event) {
            event.preventDefault();
            modal.confirm(strings.saveChanges || "", strings.confirmSave).then(function (confirmed) {
                if (!confirmed) {
                    return;
                }

                form.classList.add("is-saving");
                if (submitButton) {
                    submitButton.disabled = true;
                }

                fetch(form.getAttribute("action") || "options.php", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                    },
                    credentials: "same-origin",
                    body: serializeForm(form)
                }).then(function (response) {
                    if (!response.ok) {
                        throw new Error("save-failed");
                    }
                    headersPage.afterSave();
                    commitFormDefaults(form);
                    return modal.alert(strings.success, "");
                }).catch(function () {
                    return modal.alert(strings.error, strings.errorMessage);
                }).then(function () {
                    form.classList.remove("is-saving");
                    if (submitButton) {
                        submitButton.disabled = false;
                    }
                });
            });
        });

        if (resetButton) {
            resetButton.addEventListener("click", function () {
                modal.confirm(strings.reset || "", strings.confirmReset).then(function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    form.reset();
                    headersPage.afterReset();
                    featuresPage.afterReset();
                    updateSummaries();
                    updateCspPreview(form);
                });
            });
        }

        var copyButton = qs("[data-ash-copy]");
        if (copyButton) {
            copyButton.addEventListener("click", function () {
                copyPreview().then(function (ok) {
                    if (!ok) {
                        modal.alert(strings.error, strings.copyFailed);
                    }
                });
            });
        }
    });
})();
