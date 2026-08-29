/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : csp-runtime-observer.js
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Frontend runtime resource observer for Smart CSP discovery
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

(function () {
    "use strict";

    var config = window.ashCspObserver || {};
    if (!config.enabled || !config.endpoint || !config.token) {
        return;
    }

    var queue = {};
    var flushTimer = null;

    function originFromUrl(value) {
        if (!value) {
            return "";
        }
        var raw = String(value).trim();
        if (raw === "inline" || raw === "eval") {
            return "";
        }
        try {
            var url = new URL(raw, window.location.href);
            if (["http:", "https:", "ws:", "wss:"].indexOf(url.protocol) === -1) {
                return "";
            }
            return url.protocol + "//" + url.host;
        } catch (error) {
            return "";
        }
    }

    function add(url, type) {
        var origin = originFromUrl(url);
        if (!origin) {
            return;
        }
        queue[origin + "|" + type] = {
            origin: origin,
            type: type || "unknown"
        };
        if (!flushTimer) {
            flushTimer = window.setTimeout(flush, 4000);
        }
    }

    function scanDom() {
        var nodes = document.querySelectorAll("script[src], link[rel='stylesheet'][href], img[src], iframe[src], video[src], audio[src], source[src], object[data], embed[src], form[action], base[href], link[rel='preload'][href]");
        Array.prototype.forEach.call(nodes, function (node) {
            var tag = (node.tagName || "").toLowerCase();
            var rel = (node.getAttribute("rel") || "").toLowerCase();
            var asAttr = (node.getAttribute("as") || "").toLowerCase();
            var url = node.src || node.href || node.getAttribute("data") || node.action || "";
            var type = "unknown";
            if (tag === "script") {
                type = "script";
            } else if (tag === "link" && (rel === "stylesheet" || asAttr === "style")) {
                type = "stylesheet";
            } else if (tag === "link" && asAttr === "font") {
                type = "font";
            } else if (tag === "img") {
                type = "img";
            } else if (tag === "iframe") {
                type = "iframe";
            } else if (tag === "video" || tag === "audio" || tag === "source") {
                type = "media";
            } else if (tag === "object" || tag === "embed") {
                type = "object";
            } else if (tag === "form") {
                type = "form";
            } else if (tag === "base") {
                type = "base";
            }
            add(url, type);
        });
    }

    function flush() {
        flushTimer = null;
        var items = [];
        Object.keys(queue).forEach(function (key) {
            items.push(queue[key]);
        });
        queue = {};
        if (!items.length) {
            return;
        }

        var body = new URLSearchParams();
        body.append("action", "ash_csp_runtime");
        body.append("token", config.token);
        body.append("page", config.page || "/");
        body.append("items", JSON.stringify(items.slice(0, 20)));

        if (navigator.sendBeacon) {
            var blob = new Blob([body.toString()], {
                type: "application/x-www-form-urlencoded; charset=UTF-8"
            });
            navigator.sendBeacon(config.endpoint, blob);
            return;
        }

        fetch(config.endpoint, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
            body: body.toString()
        }).catch(function () {
            return null;
        });
    }

    if (window.PerformanceObserver) {
        try {
            var observer = new PerformanceObserver(function (list) {
                list.getEntries().forEach(function (entry) {
                    add(entry.name, entry.initiatorType || "unknown");
                });
            });
            observer.observe({ type: "resource", buffered: true });
        } catch (error) {
            // Older browsers may not support the resource entry type.
        }
    }

    if (window.WebSocket) {
        var OriginalSocket = window.WebSocket;
        window.WebSocket = function (url, protocols) {
            add(url, "websocket");
            if (protocols !== undefined) {
                return new OriginalSocket(url, protocols);
            }
            return new OriginalSocket(url);
        };
        window.WebSocket.prototype = OriginalSocket.prototype;
        window.WebSocket.CONNECTING = OriginalSocket.CONNECTING;
        window.WebSocket.OPEN = OriginalSocket.OPEN;
        window.WebSocket.CLOSING = OriginalSocket.CLOSING;
        window.WebSocket.CLOSED = OriginalSocket.CLOSED;
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", scanDom);
    } else {
        scanDom();
    }

    window.setInterval(scanDom, 8000);
    window.addEventListener("pagehide", flush);
})();
