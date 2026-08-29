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
    var diskLoop = false;
    var diskWantCancel = false;
    var diskTickCount = 0;
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

    function formatPair(template, first, second) {
        return String(template || "")
            .replace("%1$d", String(first))
            .replace("%2$d", String(second));
    }

    function mixChannel(from, to, t) {
        return Math.round(from + (to - from) * t);
    }

    function progressColor(percent) {
        var p = Math.max(0, Math.min(100, Number(percent) || 0)) / 100;
        var red = [220, 38, 38];
        var orange = [234, 88, 12];
        var green = [22, 163, 74];
        var from = red;
        var to = orange;
        var t = p / 0.5;
        if (p >= 0.5) {
            from = orange;
            to = green;
            t = (p - 0.5) / 0.5;
        }
        return "rgb(" + mixChannel(from[0], to[0], t) + ", " + mixChannel(from[1], to[1], t) + ", " + mixChannel(from[2], to[2], t) + ")";
    }

    function diskEnabled() {
        var input = qs("[data-ash-assistant-disk]");
        return !!(input && input.checked);
    }

    function diskSnapshot(payload) {
        return payload && payload.disk_scan ? payload.disk_scan : {};
    }

    function isDiskActive(disk) {
        return !!disk && (disk.status === "counting" || disk.status === "running");
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
        if (method === "disk") {
            return strings.methodDisk || "Disk";
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

        var diskOn = !!(payload && payload.state && payload.state.disk_scan_enabled);
        var value = diskOn
            ? "manual"
            : (payload && payload.state && payload.state.duration ? payload.state.duration : "1hour");
        var learning = !!(payload && payload.learning);
        var group = qs(".ash-segmented");

        radios.forEach(function (radio) {
            radio.checked = radio.value === value;
            radio.disabled = learning || (diskOn && radio.value !== "manual");
        });

        if (group) {
            group.classList.toggle("is-disabled", learning);
            group.classList.toggle("is-locked-manual", diskOn);
            if (learning) {
                group.setAttribute("aria-disabled", "true");
            } else {
                group.removeAttribute("aria-disabled");
            }
            if (diskOn) {
                group.setAttribute("title", strings.diskManualLock || "");
            } else {
                group.removeAttribute("title");
            }
        }
    }

    function diskLabel(disk) {
        var status = disk && disk.status ? disk.status : "idle";
        if (status === "counting") {
            return strings.diskCounting || "";
        }
        if (status === "cancelled") {
            return strings.diskCancelled || "";
        }
        if (status === "error") {
            return strings.diskError || "";
        }
        if (status === "complete" && !(disk.total > 0)) {
            return strings.diskEmpty || "";
        }

        var parts = [];
        if (status === "running" || status === "complete") {
            parts.push(formatPair(strings.diskScanning || "%1$d / %2$d", disk.processed || 0, disk.total || 0));
        }
        if (status === "complete") {
            parts.unshift(strings.diskComplete || "");
        }
        if (disk && disk.found) {
            parts.push(formatString(strings.diskFound || "%d", disk.found));
        }
        return parts.filter(Boolean).join(" · ");
    }

    function renderDiskProgress(payload) {
        var wrap = qs("[data-ash-disk-scan]");
        var bar = qs("[data-ash-disk-progress-bar]");
        var track = qs("[data-ash-disk-progress]");
        var label = qs("[data-ash-disk-scan-label]");
        var title = qs("[data-ash-disk-scan-title]");
        var cancelBtn = qs("[data-ash-disk-scan-cancel]");
        if (!wrap) {
            return;
        }

        var disk = diskSnapshot(payload);
        var diskOn = !!(payload && payload.state && payload.state.disk_scan_enabled);
        var show = diskOn && disk.status && disk.status !== "idle";
        if (diskLoop && diskOn) {
            show = true;
        }
        wrap.hidden = !show;

        if (title) {
            title.textContent = strings.diskScan || "";
        }
        if (label) {
            label.textContent = disk.status ? diskLabel(disk) : (strings.diskCounting || "");
        }

        var counting = disk.status === "counting" || (diskLoop && (!disk.status || disk.status === "idle"));
        var percent = counting ? 0 : (disk.percent || 0);
        if (disk.status === "complete") {
            percent = 100;
        }
        if (track) {
            track.classList.toggle("is-counting", counting);
            track.setAttribute("aria-valuenow", String(percent));
        }
        if (bar) {
            bar.style.width = counting ? "" : percent + "%";
            bar.style.backgroundColor = progressColor(counting ? 8 : percent);
        }
        if (cancelBtn) {
            cancelBtn.hidden = !isDiskActive(disk) && !(diskLoop && diskOn);
        }
    }

    function exclusionItems() {
        return qsa("[data-ash-disk-exclusion-item]").map(function (item) {
            return item.getAttribute("data-value") || "";
        }).filter(Boolean);
    }

    function normalizeExclusion(value) {
        return String(value || "")
            .replace(/\\/g, "/")
            .replace(/^\/+|\/+$/g, "")
            .trim();
    }

    function showExclusionMessage(text, isError) {
        var message = qs("[data-ash-disk-exclusion-message]");
        if (!message) {
            return;
        }
        message.hidden = !text;
        message.textContent = text || "";
        message.classList.toggle("is-error", !!isError && !!text);
    }

    function renderExclusions(payload) {
        var wrap = qs("[data-ash-disk-exclusions]");
        var list = qs("[data-ash-disk-exclusions-list]");
        var empty = qs("[data-ash-disk-exclusions-empty]");
        if (!wrap || !list) {
            return;
        }

        var diskOn = !!(payload && payload.state && payload.state.disk_scan_enabled);
        wrap.hidden = !diskOn;
        wrap.classList.toggle("is-locked", isDiskActive(diskSnapshot(payload)) || diskLoop);

        var items = payload && payload.disk_exclusions ? payload.disk_exclusions : [];
        list.innerHTML = items.map(function (item) {
            var value = String(item || "");
            return (
                '<li class="ash-disk-exclusion" data-ash-disk-exclusion-item data-value="' + escapeHtml(value) + '">' +
                '<span class="ash-disk-exclusion__label">' + escapeHtml(value) + "</span>" +
                '<button type="button" class="ash-disk-exclusion__remove" data-ash-disk-exclusion-remove="' + escapeHtml(value) + '" aria-label="' + escapeHtml(strings.diskExclusionRemove || "") + '">&times;</button>' +
                "</li>"
            );
        }).join("");
        if (empty) {
            empty.hidden = items.length > 0;
        }
    }

    function saveExclusions(items, reset, button) {
        var data = reset ? { reset: "1" } : { exclusions: items };
        var task = function () {
            return request("ash_csp_assistant_disk_exclusions", data).then(function (result) {
                if (result && result.success) {
                    lastPayload = result.data;
                    renderExclusions(result.data);
                    showExclusionMessage("", false);
                    return;
                }
                var message = result && result.data && result.data.message
                    ? result.data.message
                    : (strings.requestFailed || "");
                showExclusionMessage(message, true);
            });
        };
        if (button) {
            return withBusy(button, task);
        }
        return task();
    }

    function addExclusion(button) {
        var input = qs("[data-ash-disk-exclusion-input]");
        var wrap = qs("[data-ash-disk-exclusions]");
        if (!input || (wrap && wrap.classList.contains("is-locked"))) {
            return;
        }
        var value = normalizeExclusion(input.value);
        if (!value) {
            return;
        }
        if (value.indexOf("..") !== -1) {
            showExclusionMessage(strings.diskExclusionInvalid || "", true);
            return;
        }
        var items = exclusionItems();
        var exists = items.some(function (item) {
            return item.toLowerCase() === value.toLowerCase();
        });
        if (exists) {
            showExclusionMessage(strings.diskExclusionExists || "", true);
            return;
        }
        items.push(value);
        input.value = "";
        saveExclusions(items, false, button);
    }

    function scopeLocked() {
        var box = qs("[data-ash-disk-scope]");
        var row = qs("[data-ash-disk-scope-row]");
        return (box && box.classList.contains("is-locked")) || (row && row.classList.contains("is-locked"));
    }

    function renderScope(payload) {
        var row = qs("[data-ash-disk-scope-row]");
        var box = qs("[data-ash-disk-scope]");
        var list = qs("[data-ash-disk-scope-list]");
        var empty = qs("[data-ash-disk-scope-empty]");
        var input = qs("[data-ash-assistant-disk-scope]");
        var diskOn = !!(payload && payload.state && payload.state.disk_scan_enabled);
        var scope = payload && payload.disk_scope ? payload.disk_scope : {};
        var enabled = !!scope.enabled;
        var locked = isDiskActive(diskSnapshot(payload)) || diskLoop;

        if (row) {
            row.hidden = !diskOn;
            row.classList.toggle("is-locked", locked);
        }
        if (input) {
            input.checked = enabled;
        }
        if (box) {
            box.hidden = !diskOn || !enabled;
            box.classList.toggle("is-locked", locked);
        }
        if (!list) {
            return;
        }

        var plugins = scope.plugins || [];
        var themes = scope.themes || [];
        var html = "";
        if (plugins.length) {
            html += '<div class="ash-disk-scope__group-title">' + escapeHtml(strings.diskScopePlugins || "Plugins") + "</div>";
            html += plugins.map(scopeItemMarkup).join("");
        }
        if (themes.length) {
            html += '<div class="ash-disk-scope__group-title">' + escapeHtml(strings.diskScopeThemes || "Themes") + "</div>";
            html += themes.map(scopeItemMarkup).join("");
        }
        list.innerHTML = html;
        list.classList.toggle("has-scroll", plugins.length + themes.length > 8);
        if (empty) {
            empty.hidden = (scope.targets || []).length > 0;
        }
    }

    function scopeItemMarkup(item) {
        var rawId = String(item.id || "");
        var htmlId = "ash-disk-scope-" + rawId.replace(/[^a-zA-Z0-9_-]/g, "-");
        var checked = item.selected ? " checked" : "";
        return (
            '<div class="ash-toggle-row">' +
            '<div class="ash-toggle-row__info">' +
            '<label class="ash-toggle-row__label" for="' + escapeHtml(htmlId) + '">' + escapeHtml(item.name || item.slug || "") + "</label>" +
            '<code class="ash-disk-scope__slug">' + escapeHtml(item.slug || "") + "</code>" +
            "</div>" +
            '<label class="ash-switch">' +
            '<input type="checkbox" id="' + escapeHtml(htmlId) + '" data-ash-disk-scope-item value="' + escapeHtml(rawId) + '"' + checked + ">" +
            '<span class="ash-switch__ui" aria-hidden="true"></span>' +
            "</label>" +
            "</div>"
        );
    }

    function selectedScopeTargets() {
        return qsa("[data-ash-disk-scope-item]:checked").map(function (input) {
            return input.value;
        });
    }

    function saveScope(enabled, replaceTargets) {
        var data = {
            enabled: enabled ? "1" : "0"
        };
        if (replaceTargets) {
            data.replace_targets = "1";
            data.targets = selectedScopeTargets();
        }
        return request("ash_csp_assistant_disk_scope", data).then(function (result) {
            if (result && result.success) {
                lastPayload = result.data;
                renderScope(result.data);
                return;
            }
            if (lastPayload) {
                renderScope(lastPayload);
            }
        }).catch(function () {
            if (lastPayload) {
                renderScope(lastPayload);
            }
        });
    }

    function maybeResumeDiskScan(payload) {
        var disk = diskSnapshot(payload);
        if (!diskEnabled() || diskLoop) {
            return;
        }
        if (disk.status === "running") {
            diskLoop = true;
            tickDisk();
            return;
        }
        if (disk.status === "counting") {
            diskLoop = true;
            waitForDiskPrepare();
        }
    }

    function waitForDiskPrepare() {
        if (diskWantCancel) {
            return cancelDiskScan();
        }
        return request("ash_csp_assistant_state", {}).then(function (result) {
            if (!result || !result.success) {
                diskLoop = false;
                return;
            }
            var payload = result.data;
            lastPayload = payload;
            renderDiskProgress(payload);
            var disk = diskSnapshot(payload);
            if (diskWantCancel) {
                return cancelDiskScan();
            }
            if (disk.status === "counting") {
                return window.setTimeout(function () {
                    waitForDiskPrepare();
                }, 700);
            }
            if (disk.status === "running") {
                return tickDisk();
            }
            diskLoop = false;
            renderPayload(payload);
        });
    }

    function startDiskScan() {
        if (!diskEnabled() || diskLoop) {
            return Promise.resolve();
        }
        diskLoop = true;
        diskWantCancel = false;
        diskTickCount = 0;
        renderDiskProgress({
            state: { disk_scan_enabled: 1 },
            disk_scan: { status: "counting", percent: 0, processed: 0, total: 0, found: 0 }
        });
        if (lastPayload) {
            renderExclusions(lastPayload);
            renderScope(lastPayload);
        }
        return request("ash_csp_assistant_disk_prepare", {}).then(function (result) {
            if (diskWantCancel) {
                return cancelDiskScan();
            }
            if (!result || !result.success) {
                diskLoop = false;
                renderDiskProgress({
                    state: { disk_scan_enabled: 1 },
                    disk_scan: { status: "error", percent: 0, processed: 0, total: 0, found: 0 }
                });
                return;
            }
            lastPayload = result.data;
            renderDiskProgress(result.data);
            var disk = diskSnapshot(result.data);
            if (disk.status === "running") {
                return tickDisk();
            }
            diskLoop = false;
            renderPayload(result.data);
        }).catch(function () {
            diskLoop = false;
            return null;
        });
    }

    function tickDisk() {
        if (diskWantCancel) {
            return cancelDiskScan();
        }
        return request("ash_csp_assistant_disk_tick", {}).then(function (result) {
            if (diskWantCancel) {
                return cancelDiskScan();
            }
            if (!result || !result.success) {
                diskLoop = false;
                renderDiskProgress({
                    state: lastPayload && lastPayload.state ? lastPayload.state : { disk_scan_enabled: 1 },
                    disk_scan: { status: "error", percent: 0, processed: 0, total: 0, found: 0 }
                });
                return;
            }

            var payload = result.data;
            lastPayload = payload;
            diskTickCount += 1;
            renderDiskProgress(payload);

            var countEl = qs("[data-ash-assistant-count]");
            if (countEl) {
                countEl.textContent = String(payload.count || 0);
            }
            if (diskTickCount % 4 === 0) {
                renderSummary(payload);
                renderRows(payload, true);
            }

            var disk = diskSnapshot(payload);
            if (disk.status === "running") {
                return tickDisk();
            }
            diskLoop = false;
            renderPayload(payload);
        }).catch(function () {
            diskLoop = false;
            return null;
        });
    }

    function cancelDiskScan() {
        diskWantCancel = true;
        return request("ash_csp_assistant_disk_cancel", {}).then(function (result) {
            diskLoop = false;
            diskWantCancel = false;
            if (result && result.success) {
                renderPayload(result.data);
            }
        }).catch(function () {
            diskLoop = false;
            diskWantCancel = false;
            return null;
        });
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
        var wrap = qs(".ash-assistant__table-wrap");
        if (wrap) {
            wrap.classList.toggle("has-scroll", sources.length > 10);
        }
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
        var diskInput = qs("[data-ash-assistant-disk]");
        var disk = diskSnapshot(payload);
        var diskActive = isDiskActive(disk) || diskLoop;

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
            startBtn.hidden = !!payload.learning || diskActive;
        }
        if (stopBtn) {
            stopBtn.hidden = !payload.learning;
        }
        syncDuration(payload);
        if (continuous && payload.state) {
            continuous.checked = !!payload.state.continuous_monitoring;
        }
        if (diskInput && payload.state) {
            diskInput.checked = !!payload.state.disk_scan_enabled;
        }
        if (banner && newCount) {
            var fresh = payload.summary && payload.summary.new ? payload.summary.new : 0;
            banner.hidden = fresh <= 0 || !!payload.learning;
            newCount.textContent = String(fresh);
        }

        renderSummary(payload);
        renderRows(payload);
        renderDiskProgress(payload);
        renderExclusions(payload);
        renderScope(payload);
        togglePolling(!!payload.learning);
        maybeResumeDiskScan(payload);
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
            if (event.key !== "Enter") {
                return;
            }
            event.preventDefault();
            if (closest(event.target, "[data-ash-disk-exclusion-input]")) {
                addExclusion(qs("[data-ash-disk-exclusion-add]"));
            }
        });

        qs("[data-ash-assistant-start]").addEventListener("click", function (event) {
            var button = event.currentTarget;
            withBusy(button, function () {
                return request("ash_csp_assistant_start", {
                    duration: selectedDuration(),
                    disk_scan: diskEnabled() ? "1" : "0"
                }).then(function (result) {
                    if (result && result.success) {
                        renderPayload(result.data);
                        startDiskScan();
                        return;
                    }
                    openModal(strings.title, "<p>" + escapeHtml(strings.requestFailed || "") + "</p>", false);
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

        qs("[data-ash-assistant-disk]").addEventListener("change", function () {
            var checkbox = this;
            var enabled = checkbox.checked;
            checkbox.disabled = true;
            if (!enabled) {
                diskWantCancel = true;
            }
            request("ash_csp_assistant_disk_toggle", {
                enabled: enabled ? "1" : "0"
            }).then(function (result) {
                if (result && result.success) {
                    renderPayload(result.data);
                    if (enabled && result.data.learning) {
                        startDiskScan();
                    }
                }
            }).catch(function () {
                return null;
            }).then(function () {
                checkbox.disabled = false;
            });
        });

        qs("[data-ash-assistant-disk-scope]").addEventListener("change", function () {
            var checkbox = this;
            if (scopeLocked()) {
                checkbox.checked = !checkbox.checked;
                return;
            }
            checkbox.disabled = true;
            saveScope(checkbox.checked, false).catch(function () {
                return null;
            }).then(function () {
                checkbox.disabled = false;
            });
        });

        qs("[data-ash-disk-scope-list]").addEventListener("change", function (event) {
            var item = closest(event.target, "[data-ash-disk-scope-item]");
            if (!item) {
                return;
            }
            if (scopeLocked()) {
                item.checked = !item.checked;
                return;
            }
            saveScope(true, true);
        });

        qs("[data-ash-disk-scan-cancel]").addEventListener("click", function (event) {
            var button = event.currentTarget;
            diskWantCancel = true;
            withBusy(button, function () {
                return cancelDiskScan();
            });
        });

        qs("[data-ash-disk-exclusion-add]").addEventListener("click", function (event) {
            addExclusion(event.currentTarget);
        });

        qs("[data-ash-disk-exclusion-reset]").addEventListener("click", function (event) {
            var wrap = qs("[data-ash-disk-exclusions]");
            if (wrap && wrap.classList.contains("is-locked")) {
                showExclusionMessage(strings.diskExclusionLocked || "", true);
                return;
            }
            saveExclusions([], true, event.currentTarget);
        });

        qs("[data-ash-disk-exclusions-list]").addEventListener("click", function (event) {
            var remove = closest(event.target, "[data-ash-disk-exclusion-remove]");
            var wrap = qs("[data-ash-disk-exclusions]");
            if (!remove) {
                return;
            }
            if (wrap && wrap.classList.contains("is-locked")) {
                showExclusionMessage(strings.diskExclusionLocked || "", true);
                return;
            }
            var value = remove.getAttribute("data-ash-disk-exclusion-remove") || "";
            var items = exclusionItems().filter(function (item) {
                return item.toLowerCase() !== value.toLowerCase();
            });
            saveExclusions(items, false);
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
                        diskWantCancel = true;
                        diskLoop = false;
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
