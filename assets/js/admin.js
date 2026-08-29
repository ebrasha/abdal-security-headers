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
     * Confirm/alert dialogs use the WordPress Modal component from wp.components.
     */
    function createModal() {
        var elementApi = window.wp && wp.element;
        var componentsApi = window.wp && wp.components;

        if (!elementApi || !componentsApi || !componentsApi.Modal) {
            return createFallbackModal();
        }

        var el = elementApi.createElement;
        var Modal = componentsApi.Modal;
        var reactRoot = null;

        function getContainer() {
            var node = document.getElementById("ash-wp-modal-root");
            if (!node) {
                node = document.createElement("div");
                node.id = "ash-wp-modal-root";
                document.body.appendChild(node);
            }
            return node;
        }

        function unmount() {
            if (reactRoot && typeof reactRoot.render === "function") {
                reactRoot.render(null);
                return;
            }
            if (typeof elementApi.unmountComponentAtNode === "function") {
                elementApi.unmountComponentAtNode(getContainer());
            }
        }

        function mount(node) {
            var container = getContainer();
            if (typeof elementApi.createRoot === "function") {
                if (!reactRoot) {
                    reactRoot = elementApi.createRoot(container);
                }
                reactRoot.render(node);
                return;
            }
            elementApi.render(node, container);
        }

        function open(options) {
            return new Promise(function (resolve) {
                var settled = false;

                function finish(result) {
                    if (settled) {
                        return;
                    }
                    settled = true;
                    unmount();
                    resolve(!!result);
                }

                var actionChildren = [];
                if (!options.alert) {
                    actionChildren.push(el("button", {
                        type: "button",
                        key: "cancel",
                        className: "button",
                        onClick: function () {
                            finish(false);
                        }
                    }, options.cancelText || strings.no || "No"));
                }

                actionChildren.push(el("button", {
                    type: "button",
                    key: "confirm",
                    className: "button button-primary",
                    onClick: function () {
                        finish(true);
                    }
                }, options.confirmText || strings.ok || "OK"));

                var modalChildren = [];
                if (options.message) {
                    modalChildren.push(el("p", {
                        key: "message",
                        className: "ash-wp-modal__message"
                    }, options.message));
                }
                modalChildren.push(el("div", {
                    key: "actions",
                    className: "ash-wp-modal__actions"
                }, actionChildren));

                mount(el(Modal, {
                    title: options.title || "",
                    className: "ash-wp-modal",
                    onRequestClose: function () {
                        finish(false);
                    }
                }, modalChildren));
            });
        }

        return {
            confirm: function (title, message) {
                return open({
                    title: title,
                    message: message,
                    confirmText: strings.yes,
                    cancelText: strings.no,
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
        qsa("input", form).forEach(function (input) {
            if (input.type === "checkbox") {
                input.defaultChecked = input.checked;
            } else {
                input.defaultValue = input.value;
            }
        });
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

    ready(function () {
        var form = qs("#ash-settings-form");
        if (!form) {
            return;
        }

        var modal = createModal();
        var submitButton = qs("#ash-submit-button", form);
        var resetButton = qs("#ash-reset-button", form);

        bindHelp();
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
            modal.confirm(strings.confirmSave, "").then(function (confirmed) {
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
                modal.confirm(strings.confirmReset, "").then(function (confirmed) {
                    if (!confirmed) {
                        return;
                    }
                    form.reset();
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
