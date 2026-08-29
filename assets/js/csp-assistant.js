/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : csp-assistant.js
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Admin UI for the Smart CSP Assistant hybrid discovery engine
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

(function () {
    "use strict";

    var config = window.ashCspAssistant || {};
    var strings = config.strings || {};
    var pollTimer = null;
    var pendingIds = [];
    var lastPayload = null;
    var optionMap = config.optionMap || {
        "script-src": "csp_script_src",
        "style-src": "csp_style_src",
        "img-src": "csp_img_src",
        "font-src": "csp_font_src",
        "connect-src": "csp_connect_src",
        "frame-src": "csp_frame_src",
        "media-src": "csp_media_src",
        "worker-src": "csp_worker_src",
        "form-action": "csp_form_action",
        "base-uri": "csp_base_uri",
        "object-src": "csp_object_src",
        "default-src": "csp_default_src"
    };

    function closest(element, selector) {
        while (element && element.nodeType === 1) {
            if (element.matches && element.matches(selector)) {
                return element;
            }
            element = element.parentElement;
        }
        return null;
    }

    function qs(selector, root) {
        return (root || document).querySelector(selector);
    }

    function qsa(selector, root) {
        return Array.prototype.slice.call((root || document).querySelectorAll(selector));
    }

    function escapeHtml(value) {
        var node = document.createElement("div");
        node.textContent = value == null ? "" : String(value);
        return node.innerHTML;
    }

    function formatString(template, value) {
        return String(template || "").replace("%d", String(value));
    }

    function methodLabel(method) {
        if (method === "static") {
            return strings.methodStatic || "Static";
        }
        if (method === "report-only") {
            return strings.methodReport || "Report-Only";
        }
        if (method === "runtime") {
            return strings.methodRuntime || "Runtime";
        }
        return method;
    }

    function confidenceLabel(value) {
        var map = {
            trusted: strings.trusted,
            likely_safe: strings.likelySafe,
            unknown: strings.unknown,
            potentially_risky: strings.potentiallyRisky
        };
        return map[value] || value;
    }

    function statusLabel(value) {
        var map = {
            new: strings.statusNew,
            ignored: strings.statusIgnored,
            applied: strings.statusApplied,
            added: strings.statusAdded,
            warning: strings.statusWarning
        };
        return map[value] || value;
    }

    function statusMarkup(value) {
        var cls = "ash-assistant-status";
        if (value === "added") {
            cls += " ash-assistant-status--added";
        }
        return '<span class="' + cls + '">' + escapeHtml(statusLabel(value)) + "</span>";
    }

    function originHost(origin) {
        var match = String(origin || "").match(/^(https?|wss?):\/\/([^/?#]+)/i);
        return match ? match[2].toLowerCase() : "";
    }

    function originScheme(origin) {
        var match = String(origin || "").match(/^(https?|wss?):\/\//i);
        return match ? match[1].toLowerCase() : "";
    }

    function isSiteOrigin(origin) {
        var siteHost = String(config.siteHost || "").toLowerCase();
        var host = originHost(origin);
        if (!host || !siteHost) {
            return false;
        }
        if (host === siteHost) {
            return true;
        }
        return (host.indexOf("www.") === 0 && host.slice(4) === siteHost)
            || (siteHost.indexOf("www.") === 0 && siteHost.slice(4) === host);
    }

    function tokenCoversOrigin(token, origin) {
        token = String(token || "").replace(/\/+$/, "").trim();
        origin = String(origin || "").replace(/\/+$/, "").trim();
        if (!token || !origin) {
            return false;
        }
        if (token.toLowerCase() === origin.toLowerCase()) {
            return true;
        }

        var keyword = token.replace(/^['"]+|['"]+$/g, "").toLowerCase();
        if (keyword === "self" && isSiteOrigin(origin)) {
            return true;
        }
        if (token === "*" || keyword === "*") {
            return true;
        }
        if (token === "https:" && origin.toLowerCase().indexOf("https://") === 0) {
            return true;
        }
        if (token === "http:" && origin.toLowerCase().indexOf("http://") === 0) {
            return true;
        }

        var tokenScheme = "";
        var tokenHost = token.toLowerCase();
        var parsed = token.match(/^(https?|wss?):\/\/([^/?#]+)/i);
        if (parsed) {
            tokenScheme = parsed[1].toLowerCase();
            tokenHost = parsed[2].toLowerCase();
        }

        var host = originHost(origin);
        var scheme = originScheme(origin);
        if (!host) {
            return false;
        }
        if (tokenScheme && tokenScheme !== scheme) {
            return false;
        }
        if (tokenHost.indexOf("*.") === 0) {
            var suffix = tokenHost.slice(1);
            return host.slice(-suffix.length) === suffix;
        }
        return tokenHost === host;
    }

    function policyCoversOrigin(policyValue, origin) {
        var tokens = String(policyValue || "").trim().split(/\s+/);
        var i;
        for (i = 0; i < tokens.length; i += 1) {
            if (tokens[i] && tokenCoversOrigin(tokens[i], origin)) {
                return true;
            }
        }
        return false;
    }

    function livePolicyValue(directive) {
        var field = qs('[data-csp-directive="' + directive + '"]');
        if (field) {
            return field.value;
        }
        var key = optionMap[directive];
        if (key) {
            var byId = document.getElementById(key);
            if (byId) {
                return byId.value;
            }
        }
        return null;
    }

    function sourceInPolicy(source) {
        var live = livePolicyValue(source.directive);
        if (live !== null) {
            if (policyCoversOrigin(live, source.origin)) {
                return true;
            }
            if (String(live).trim() !== "" || source.directive === "default-src") {
                return false;
            }
            var fallback = livePolicyValue("default-src");
            return fallback !== null && policyCoversOrigin(fallback, source.origin);
        }
        return !!source.in_policy;
    }

    function displayStatus(source) {
        if (sourceInPolicy(source)) {
            return "added";
        }
        return source.db_status || source.status;
    }

    function isSelectable(source) {
        var status = displayStatus(source);
        return source.directive !== "unknown" && status !== "ignored" && status !== "added";
    }

    function spinnerMarkup() {
        return '<span class="ash-spinner" aria-hidden="true"></span>';
    }

    function ensureSpinner(button) {
        if (!button || qs(".ash-spinner", button)) {
            return;
        }
        var spinner = document.createElement("span");
        spinner.className = "ash-spinner";
        spinner.setAttribute("aria-hidden", "true");
        button.appendChild(spinner);
    }

    function setBusy(button, busy) {
        if (!button) {
            return;
        }
        ensureSpinner(button);
        button.classList.toggle("is-busy", !!busy);
        button.disabled = !!busy;
        button.setAttribute("aria-busy", busy ? "true" : "false");
    }

    function withBusy(button, task) {
        if (!button || button.classList.contains("is-busy")) {
            return Promise.resolve();
        }
        setBusy(button, true);
        return Promise.resolve()
            .then(task)
            .catch(function () {
                return null;
            })
            .then(function (result) {
                if (button && button.isConnected) {
                    setBusy(button, false);
                }
                return result;
            });
    }

    function request(action, data) {
        var body = new URLSearchParams();
        body.append("action", action);
        body.append("nonce", config.nonce || "");
        Object.keys(data || {}).forEach(function (key) {
            var value = data[key];
            if (Array.isArray(value)) {
                value.forEach(function (item) {
                    body.append(key + "[]", item);
                });
            } else {
                body.append(key, value);
            }
        });

        return fetch(config.ajaxUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
            body: body.toString()
        }).then(function (response) {
            return response.json();
        });
    }

    function selectedIds(root) {
        return qsa("[data-ash-source-id]:checked", root).map(function (input) {
            return input.getAttribute("data-ash-source-id");
        });
    }

    function selectedDuration() {
        var checked = qs("[data-ash-assistant-duration]:checked");
        return checked && checked.value ? checked.value : "1hour";
    }

    function syncDuration(payload) {
        var radios = qsa("[data-ash-assistant-duration]");
        if (!radios.length) {
            return;
        }

        var value = payload && payload.state && payload.state.duration ? payload.state.duration : "1hour";
        var disabled = !!(payload && payload.learning);
        var group = qs(".ash-segmented");

        radios.forEach(function (radio) {
            radio.checked = radio.value === value;
            radio.disabled = disabled;
        });

        if (group) {
            group.classList.toggle("is-disabled", disabled);
            if (disabled) {
                group.setAttribute("aria-disabled", "true");
            } else {
                group.removeAttribute("aria-disabled");
            }
        }
    }

    function renderSummary(payload) {
        var summaryEl = qs("[data-ash-assistant-summary]");
        if (!summaryEl) {
            return;
        }
        var summary = payload.summary || {};
        var by = summary.by_directive || {};
        if (!summary.total) {
            summaryEl.innerHTML = "";
            return;
        }

        var cards = [
            { label: formatString(strings.summaryTotal, summary.total) },
            { label: formatString(strings.summaryScript, by["script-src"] || 0) },
            { label: formatString(strings.summaryStyle, by["style-src"] || 0) },
            { label: formatString(strings.summaryImg, by["img-src"] || 0) },
            { label: formatString(strings.summaryFont, by["font-src"] || 0) },
            { label: formatString(strings.summaryConnect, by["connect-src"] || 0) },
            { label: formatString(strings.summaryFrame, by["frame-src"] || 0) }
        ];

        summaryEl.innerHTML = cards.map(function (card) {
            return '<article class="ash-assistant-stat"><span>' + escapeHtml(card.label) + "</span></article>";
        }).join("");
    }

    function renderRows(payload, preserveSelection) {
        var body = qs("[data-ash-assistant-rows]");
        if (!body) {
            return;
        }
        var sources = payload.sources || [];
        if (!sources.length) {
            body.innerHTML = '<tr><td colspan="8">' + escapeHtml(strings.empty || "") + "</td></tr>";
            return;
        }

        var previouslySelected = {};
        if (preserveSelection) {
            qsa("[data-ash-source-id]:checked").forEach(function (input) {
                previouslySelected[input.getAttribute("data-ash-source-id")] = true;
            });
        }

        body.innerHTML = sources.map(function (source) {
            var methods = (source.detection_methods || []).map(methodLabel).join(" + ");
            var page = (source.pages_detected && source.pages_detected[0]) ? source.pages_detected[0] : "—";
            var status = displayStatus(source);
            var selectable = isSelectable(source);
            var dbStatus = source.db_status || source.status;
            var disabled = selectable ? "" : " disabled";
            var checked = "";
            if (selectable) {
                if (preserveSelection) {
                    if (previouslySelected[String(source.id)]) {
                        checked = " checked";
                    }
                } else if ((source.db_status || source.status) === "new") {
                    checked = " checked";
                }
            }
            return (
                "<tr>" +
                '<td><input type="checkbox" data-ash-source-id="' + escapeHtml(source.id) + '"' + disabled + checked + "></td>" +
                '<td><code class="ash-assistant-origin">' + escapeHtml(source.origin) + "</code></td>" +
                "<td>" + escapeHtml(source.directive) + "</td>" +
                "<td>" + escapeHtml(methods) + "</td>" +
                "<td>" + escapeHtml(page) + "</td>" +
                '<td><span class="ash-assistant-confidence ash-assistant-confidence--' + escapeHtml(source.confidence) + '">' + escapeHtml(confidenceLabel(source.confidence)) + "</span></td>" +
                "<td>" + statusMarkup(status) + "</td>" +
                "<td>" +
                '<div class="ash-assistant-row-actions">' +
                '<button type="button" class="ash-btn ash-btn--secondary" data-ash-source-add="' + escapeHtml(source.id) + '"' + (selectable ? "" : " disabled") + ">" + escapeHtml(strings.add || "Add") + spinnerMarkup() + "</button>" +
                '<button type="button" class="ash-btn ash-btn--secondary" data-ash-source-ignore="' + escapeHtml(source.id) + '"' + (dbStatus === "ignored" ? " disabled" : "") + ">" + escapeHtml(strings.ignore || "Ignore") + spinnerMarkup() + "</button>" +
                '<button type="button" class="ash-btn ash-btn--secondary" data-ash-source-details="' + escapeHtml(source.id) + '">' + escapeHtml(strings.details || "Details") + spinnerMarkup() + "</button>" +
                "</div>" +
                "</td>" +
                "</tr>"
            );
        }).join("");
    }

    function refreshPolicyStatus() {
        if (lastPayload) {
            renderRows(lastPayload, true);
        }
    }

    function renderPayload(payload) {
        if (!payload) {
            return;
        }
        lastPayload = payload;

        var statusEl = qs("[data-ash-assistant-status]");
        var countEl = qs("[data-ash-assistant-count]");
        var learningEl = qs("[data-ash-assistant-learning]");
        var startBtn = qs("[data-ash-assistant-start]");
        var stopBtn = qs("[data-ash-assistant-stop]");
        var banner = qs("[data-ash-assistant-new]");
        var newCount = qs("[data-ash-assistant-new-count]");
        var continuous = qs("[data-ash-assistant-continuous]");

        if (statusEl) {
            statusEl.textContent = payload.status_label || "";
        }
        if (countEl) {
            countEl.textContent = String(payload.count || 0);
        }
        if (learningEl) {
            learningEl.hidden = !payload.learning;
        }
        if (startBtn) {
            startBtn.hidden = !!payload.learning;
        }
        if (stopBtn) {
            stopBtn.hidden = !payload.learning;
        }
        syncDuration(payload);
        if (continuous && payload.state) {
            continuous.checked = !!payload.state.continuous_monitoring;
        }
        if (banner && newCount) {
            var fresh = payload.summary && payload.summary.new ? payload.summary.new : 0;
            banner.hidden = fresh <= 0 || !!payload.learning;
            newCount.textContent = String(fresh);
        }

        renderSummary(payload);
        renderRows(payload);
        togglePolling(!!payload.learning);
    }

    function togglePolling(enabled) {
        if (enabled && !pollTimer) {
            pollTimer = window.setInterval(function () {
                request("ash_csp_assistant_state", {}).then(function (result) {
                    if (result && result.success) {
                        renderPayload(result.data);
                    }
                });
            }, 8000);
        }
        if (!enabled && pollTimer) {
            window.clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function openModal(title, html, showConfirm) {
        var modal = qs("#ash-assistant-modal");
        var titleEl = qs("#ash-assistant-modal-title");
        var bodyEl = qs("#ash-assistant-modal-body");
        var confirmBtn = qs("[data-ash-assistant-modal-confirm]");
        if (!modal || !titleEl || !bodyEl) {
            return;
        }
        titleEl.textContent = title || "";
        bodyEl.innerHTML = html || "";
        if (confirmBtn) {
            confirmBtn.hidden = !showConfirm;
        }
        modal.hidden = false;
        document.body.classList.add("ash-modal-open");
    }

    function closeModal() {
        var modal = qs("#ash-assistant-modal");
        if (modal) {
            modal.hidden = true;
        }
        document.body.classList.remove("ash-modal-open");
        pendingIds = [];
    }

    function renderDiff(diff) {
        if (!diff || !diff.changes || !diff.changes.length) {
            return "<p>" + escapeHtml(strings.noSelection || "") + "</p>";
        }
        var html = diff.changes.map(function (change) {
            var added = (change.added || []).map(function (item) {
                return '<div class="ash-assistant-diff__new">+ ' + escapeHtml(item) + "</div>";
            }).join("");
            return (
                '<section class="ash-assistant-diff">' +
                "<h3>" + escapeHtml(change.directive) + "</h3>" +
                "<p><strong>" + escapeHtml(strings.current || "") + ":</strong> <code>" + escapeHtml(change.current || "—") + "</code></p>" +
                "<p><strong>" + escapeHtml(strings.proposed || "") + ":</strong> <code>" + escapeHtml(change.proposed || "") + "</code></p>" +
                "<p><strong>" + escapeHtml(strings.newToken || "") + ":</strong></p>" +
                added +
                "</section>"
            );
        }).join("");

        if (diff.skipped_unknown) {
            html += "<p>" + escapeHtml(strings.unknownSkip || "") + "</p>";
        }
        if (diff.has_dangerous) {
            html += '<label class="ash-assistant__continuous"><input type="checkbox" data-ash-confirm-dangerous> <span>' + escapeHtml(strings.confirmDangerous || "") + "</span></label>";
            html += "<p>" + escapeHtml(strings.dangerousWarning || "") + "</p>";
        }
        return html;
    }

    function applyUpdatedOptions(updated) {
        if (!updated) {
            return;
        }
        Object.keys(updated).forEach(function (id) {
            var input = document.getElementById(id);
            if (input) {
                input.value = updated[id];
                input.dispatchEvent(new Event("input", { bubbles: true }));
            }
        });
    }

    function showDetails(id, button) {
        return withBusy(button, function () {
            return request("ash_csp_assistant_details", { id: id }).then(function (result) {
                if (!result || !result.success) {
                    openModal(strings.details, "<p>" + escapeHtml(strings.requestFailed || "") + "</p>", false);
                    return;
                }
                var source = result.data;
                var status = displayStatus(source);
                var rows = [
                    [strings.origin, escapeHtml(source.origin)],
                    [strings.colDirective, escapeHtml(source.directive)],
                    [strings.resourceType, escapeHtml(source.resource_type || "—")],
                    [strings.detectionMethods, escapeHtml((source.detection_methods || []).map(methodLabel).join(" + "))],
                    [strings.firstSeen, escapeHtml(source.first_seen)],
                    [strings.lastSeen, escapeHtml(source.last_seen)],
                    [strings.detectionCount, escapeHtml(source.detection_count)],
                    [strings.pagesDetected, escapeHtml((source.pages_detected || []).join(", ") || "—")],
                    [strings.colConfidence, escapeHtml(confidenceLabel(source.confidence))],
                    [strings.colStatus, statusMarkup(status)]
                ];
                if (source.detected_from) {
                    rows.push([strings.detectedFrom, escapeHtml(source.detected_from)]);
                }
                if (source.dangerous) {
                    rows.push([strings.statusWarning, escapeHtml(strings.dangerousWarning)]);
                }
                var html = '<dl class="ash-assistant-details">' + rows.map(function (row) {
                    return "<dt>" + escapeHtml(row[0]) + "</dt><dd>" + row[1] + "</dd>";
                }).join("") + "</dl>";
                openModal(strings.details, html, false);
            });
        });
    }

    function startApply(ids, button) {
        if (!ids.length) {
            openModal(strings.applySelected, "<p>" + escapeHtml(strings.noSelection || "") + "</p>", false);
            return Promise.resolve();
        }
        return withBusy(button, function () {
            return request("ash_csp_assistant_diff", { ids: ids }).then(function (result) {
                if (!result || !result.success) {
                    openModal(strings.policyDiff, "<p>" + escapeHtml(strings.requestFailed || "") + "</p>", false);
                    return;
                }
                pendingIds = ids;
                openModal(strings.policyDiff, renderDiff(result.data.diff), true);
            });
        });
    }

    function bind() {
        var root = qs("[data-ash-assistant]");
        if (!root) {
            return;
        }

        renderPayload(config.initial || {});

        var form = qs("#ash-settings-form");
        if (form) {
            form.addEventListener("input", function (event) {
                if (event.target && event.target.getAttribute("data-csp-directive") !== null) {
                    refreshPolicyStatus();
                }
            });
        }

        root.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
            }
        });

        qs("[data-ash-assistant-start]").addEventListener("click", function (event) {
            var button = event.currentTarget;
            withBusy(button, function () {
                return request("ash_csp_assistant_start", {
                    duration: selectedDuration()
                }).then(function (result) {
                    if (result && result.success) {
                        renderPayload(result.data);
                    } else {
                        openModal(strings.title, "<p>" + escapeHtml(strings.requestFailed || "") + "</p>", false);
                    }
                });
            });
        });

        qs("[data-ash-assistant-stop]").addEventListener("click", function (event) {
            var button = event.currentTarget;
            withBusy(button, function () {
                return request("ash_csp_assistant_stop", {}).then(function (result) {
                    if (result && result.success) {
                        renderPayload(result.data);
                    }
                });
            });
        });

        qs("[data-ash-assistant-review]").addEventListener("click", function () {
            var table = qs(".ash-assistant__table-wrap");
            if (table) {
                table.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        });

        qs("[data-ash-assistant-apply]").addEventListener("click", function (event) {
            startApply(selectedIds(root), event.currentTarget);
        });

        qs("[data-ash-assistant-clear]").addEventListener("click", function () {
            pendingIds = ["__clear__"];
            openModal(strings.clearData, "<p>" + escapeHtml(strings.confirmClear || "") + "</p>", true);
        });

        qs("[data-ash-assistant-continuous]").addEventListener("change", function () {
            var checkbox = this;
            checkbox.disabled = true;
            request("ash_csp_assistant_continuous", {
                enabled: checkbox.checked ? "1" : "0"
            }).then(function (result) {
                if (result && result.success) {
                    renderPayload(result.data);
                }
            }).catch(function () {
                return null;
            }).then(function () {
                checkbox.disabled = false;
            });
        });

        qs("[data-ash-assistant-check-all]").addEventListener("change", function () {
            var checked = this.checked;
            qsa("[data-ash-source-id]", root).forEach(function (input) {
                if (!input.disabled) {
                    input.checked = checked;
                }
            });
        });

        root.addEventListener("click", function (event) {
            var add = closest(event.target, "[data-ash-source-add]");
            var ignore = closest(event.target, "[data-ash-source-ignore]");
            var details = closest(event.target, "[data-ash-source-details]");
            if (add) {
                startApply([add.getAttribute("data-ash-source-add")], add);
            }
            if (ignore) {
                withBusy(ignore, function () {
                    return request("ash_csp_assistant_ignore", {
                        id: ignore.getAttribute("data-ash-source-ignore")
                    }).then(function (result) {
                        if (result && result.success) {
                            renderPayload(result.data);
                        }
                    });
                });
            }
            if (details) {
                showDetails(details.getAttribute("data-ash-source-details"), details);
            }
        });

        qs("[data-ash-assistant-modal-dismiss]").addEventListener("click", closeModal);
        qs("[data-ash-assistant-modal-cancel]").addEventListener("click", closeModal);
        qs("[data-ash-assistant-modal-confirm]").addEventListener("click", function (event) {
            var button = event.currentTarget;
            if (pendingIds[0] === "__clear__") {
                withBusy(button, function () {
                    return request("ash_csp_assistant_clear", {}).then(function (result) {
                        closeModal();
                        if (result && result.success) {
                            renderPayload(result.data);
                        }
                    });
                });
                return;
            }

            var dangerous = qs("[data-ash-confirm-dangerous]");
            withBusy(button, function () {
                return request("ash_csp_assistant_apply", {
                    ids: pendingIds,
                    confirm_dangerous: dangerous && dangerous.checked ? "1" : "0"
                }).then(function (result) {
                    if (!result || !result.success) {
                        var message = result && result.data && result.data.message ? result.data.message : strings.requestFailed;
                        qs("#ash-assistant-modal-body").innerHTML = "<p>" + escapeHtml(message) + "</p>" + (result && result.data && result.data.diff ? renderDiff(result.data.diff) : "");
                        return;
                    }
                    applyUpdatedOptions(result.data.updated_options);
                    closeModal();
                    renderPayload(result.data);
                });
            });
        });

        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape") {
                closeModal();
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bind);
    } else {
        bind();
    }
})();
