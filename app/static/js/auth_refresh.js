/**
 * Renovación Silenciosa de Sesión JWT, Protección CSRF y Seguridad de Formularios
 */
(function () {
    "use strict";

    var AUTO_REFRESH_INTERVAL_MS = 25 * 60 * 1000;
    var REFRESH_ENDPOINT = "/auth/refresh";
    var LOGIN_ENDPOINT = "/auth/login";
    var LOGIN_EXPIRED_URL = "/login?expired=1";
    var UNSAFE_METHODS = { POST: true, PUT: true, PATCH: true, DELETE: true };

    var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
    var refreshInFlightPromise = null;
    var refreshIntervalId = null;

    function getCookieValue(name) {
        if (!document || !document.cookie) {
            return "";
        }
        var cookies = document.cookie.split(";");
        for (var i = 0; i < cookies.length; i++) {
            var part = cookies[i].trim();
            if (part.indexOf(name + "=") === 0) {
                return decodeURIComponent(part.substring(name.length + 1));
            }
        }
        return "";
    }

    function getCsrfToken() {
        var cookieToken = getCookieValue("csrf_token");
        if (cookieToken) {
            return cookieToken;
        }
        var metaEl = document.querySelector('meta[name="csrf-token"]');
        if (metaEl) {
            return metaEl.getAttribute("content") || "";
        }
        return "";
    }

    function syncCsrfTokenInDom(newToken) {
        var tokenToSync = newToken || getCookieValue("csrf_token");
        if (!tokenToSync) {
            return;
        }
        var metaEl = document.querySelector('meta[name="csrf-token"]');
        if (metaEl) {
            metaEl.setAttribute("content", tokenToSync);
        }
        var hiddenInputs = document.querySelectorAll('input[name="csrf_token"]');
        for (var i = 0; i < hiddenInputs.length; i++) {
            hiddenInputs[i].value = tokenToSync;
        }
    }

    function isSameOrigin(urlStr) {
        if (!urlStr) {
            return true;
        }
        if (urlStr.indexOf("/") === 0 && urlStr.indexOf("//") !== 0) {
            return true;
        }
        try {
            var parsed = new URL(urlStr, window.location.origin);
            return parsed.origin === window.location.origin;
        } catch (err) {
            return false;
        }
    }

    function extractPathname(input) {
        try {
            var rawUrl = typeof input === "string"
                ? input
                : (input && input.url ? input.url : String(input));
            var parsed = new URL(rawUrl, window.location.origin);
            return parsed.pathname || "";
        } catch (err) {
            return typeof input === "string" ? input : "";
        }
    }

    function isAuthenticatedView() {
        return Boolean(
            (document.body && document.body.getAttribute("data-authenticated") === "true") ||
            document.querySelector(".user-pill") ||
            document.querySelector('form[action="/auth/logout"]')
        );
    }

    function performSilentRefresh() {
        if (!nativeFetch) {
            return Promise.resolve(false);
        }
        if (refreshInFlightPromise) {
            return refreshInFlightPromise;
        }

        var csrfToken = getCsrfToken();
        var headers = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        };
        if (csrfToken) {
            headers["X-CSRF-Token"] = csrfToken;
        }

        refreshInFlightPromise = nativeFetch(REFRESH_ENDPOINT, {
            method: "POST",
            credentials: "same-origin",
            headers: headers
        })
            .then(function (response) {
                if (!response.ok) {
                    return false;
                }
                return response
                    .clone()
                    .json()
                    .then(function (data) {
                        if (data && data.csrf_token) {
                            syncCsrfTokenInDom(data.csrf_token);
                        } else {
                            syncCsrfTokenInDom("");
                        }
                        return true;
                    })
                    .catch(function () {
                        syncCsrfTokenInDom("");
                        return true;
                    });
            })
            .catch(function () {
                return false;
            })
            .finally(function () {
                refreshInFlightPromise = null;
            });

        return refreshInFlightPromise;
    }

    if (nativeFetch) {
        window.fetch = function (input, init) {
            var options = init ? Object.assign({}, init) : {};
            var method = (
                options.method ||
                (input && input.method) ||
                "GET"
            ).toUpperCase();

            var rawUrl = typeof input === "string"
                ? input
                : (input && input.url ? input.url : "");

            var sameOrigin = isSameOrigin(rawUrl);
            var pathname = extractPathname(input);
            var isExcludedAuthRoute =
                pathname.indexOf(LOGIN_ENDPOINT) === 0 ||
                pathname.indexOf(REFRESH_ENDPOINT) === 0;

            var preparePromise = Promise.resolve();
            if (
                sameOrigin &&
                UNSAFE_METHODS[method] &&
                !isExcludedAuthRoute &&
                isAuthenticatedView() &&
                !getCookieValue("csrf_token")
            ) {
                preparePromise = performSilentRefresh().then(function () {});
            }

            return preparePromise.then(function () {
                if (sameOrigin) {
                    if (!options.credentials) {
                        options.credentials = "same-origin";
                    }
                    var headers = new Headers(
                        options.headers || (input instanceof Request ? input.headers : undefined)
                    );
                    var csrfToken = getCsrfToken();
                    if (csrfToken && (UNSAFE_METHODS[method] || !headers.has("X-CSRF-Token"))) {
                        headers.set("X-CSRF-Token", csrfToken);
                    }
                    options.headers = headers;
                }

                return nativeFetch(input, options).then(function (response) {
                    if (
                        response.status === 403 &&
                        sameOrigin &&
                        UNSAFE_METHODS[method] &&
                        !isExcludedAuthRoute &&
                        !options._retriedAfterCsrf
                    ) {
                        return performSilentRefresh().then(function (refreshed) {
                            if (!refreshed) {
                                return response;
                            }
                            var retryCsrfOptions = Object.assign({}, options, { _retriedAfterCsrf: true });
                            var retryCsrfHeaders = new Headers(retryCsrfOptions.headers);
                            var updatedCsrf = getCsrfToken();
                            if (updatedCsrf) {
                                retryCsrfHeaders.set("X-CSRF-Token", updatedCsrf);
                            }
                            retryCsrfOptions.headers = retryCsrfHeaders;
                            return nativeFetch(input, retryCsrfOptions);
                        });
                    }

                    if (response.status !== 401 || isExcludedAuthRoute || options._retriedAfterRefresh) {
                        return response;
                    }

                    return performSilentRefresh().then(function (refreshed) {
                        if (!refreshed) {
                            if (
                                window.location.pathname.indexOf("/login") !== 0 &&
                                window.location.pathname.indexOf("/register") !== 0
                            ) {
                                window.location.replace(LOGIN_EXPIRED_URL);
                            }
                            return response;
                        }

                        var retryOptions = Object.assign({}, options, { _retriedAfterRefresh: true });
                        var retryHeaders = new Headers(retryOptions.headers);
                        var updatedCsrf = getCsrfToken();
                        if (updatedCsrf) {
                            retryHeaders.set("X-CSRF-Token", updatedCsrf);
                        }
                        retryOptions.headers = retryHeaders;
                        return nativeFetch(input, retryOptions);
                    });
                });
            });
        };
    }

    function initAutoRefreshTimer() {
        syncCsrfTokenInDom("");

        if (!isAuthenticatedView()) {
            return;
        }

        if (refreshIntervalId !== null) {
            clearInterval(refreshIntervalId);
        }

        refreshIntervalId = window.setInterval(function () {
            performSilentRefresh().then(function (ok) {
                if (!ok) {
                    clearInterval(refreshIntervalId);
                    refreshIntervalId = null;
                }
            });
        }, AUTO_REFRESH_INTERVAL_MS);
    }

    function setToggleVisualState(btn, isVisible) {
        if (!btn) {
            return;
        }
        btn.setAttribute("aria-pressed", isVisible ? "true" : "false");
        btn.setAttribute("aria-label", isVisible ? "Ocultar contraseña" : "Mostrar contraseña");
        btn.classList.toggle("is-visible", isVisible);
        var eyeOpen = btn.querySelector(".icon-eye");
        var eyeOff = btn.querySelector(".icon-eye-off");
        if (eyeOpen) {
            eyeOpen.hidden = isVisible;
        }
        if (eyeOff) {
            eyeOff.hidden = !isVisible;
        }
    }

    var passwordToggleBound = false;

    function initPasswordToggles() {
        if (passwordToggleBound) {
            return;
        }
        passwordToggleBound = true;
        document.addEventListener("click", function (event) {
            var target = event.target;
            if (!target || typeof target.closest !== "function") {
                return;
            }
            var btn = target.closest("[data-toggle-password]");
            if (!btn) {
                return;
            }
            event.preventDefault();
            event.stopPropagation();

            var targetId = btn.getAttribute("data-toggle-password");
            var input = targetId ? document.getElementById(targetId) : null;
            if (!input) {
                return;
            }
            var isHidden = input.type === "password";
            input.type = isHidden ? "text" : "password";
            input.setAttribute("data-was-password", "true");
            setToggleVisualState(btn, isHidden);
        });
    }

    function restorePasswordTypesInScope(rootEl) {
        var scope = rootEl || document;
        var inputs = scope.querySelectorAll('input[data-was-password="true"]');
        for (var i = 0; i < inputs.length; i++) {
            inputs[i].type = "password";
            var btn = scope.querySelector('[data-toggle-password="' + inputs[i].id + '"]');
            setToggleVisualState(btn, false);
        }
    }

    function clearSensitiveInputs() {
        var inputs = document.querySelectorAll('input[type="password"], input[data-was-password="true"]');
        for (var i = 0; i < inputs.length; i++) {
            inputs[i].value = "";
            if (inputs[i].getAttribute("data-was-password") === "true") {
                inputs[i].type = "password";
                var btn = document.querySelector('[data-toggle-password="' + inputs[i].id + '"]');
                setToggleVisualState(btn, false);
            }
        }
    }

    function clearClientStorage() {
        try {
            if (window.localStorage) {
                window.localStorage.clear();
            }
            if (window.sessionStorage) {
                window.sessionStorage.clear();
            }
        } catch (err) {}
    }

    function bindPasswordSubmitProtection() {
        document.addEventListener(
            "submit",
            function (event) {
                var form = event.target;
                if (form && typeof form.querySelectorAll === "function") {
                    restorePasswordTypesInScope(form);
                }
            },
            true
        );
    }

    function bindPasswordMatch(formId, pwdId, confirmId, feedbackId) {
        var form = document.getElementById(formId);
        var newPwd = document.getElementById(pwdId);
        var confirmPwd = document.getElementById(confirmId);
        var feedback = document.getElementById(feedbackId);
        if (!form || !newPwd || !confirmPwd || !feedback) {
            return null;
        }

        function updateMatch() {
            var a = newPwd.value || "";
            var b = confirmPwd.value || "";
            if (!b) {
                feedback.textContent = "";
                feedback.className = "password-match-feedback";
                confirmPwd.setCustomValidity("");
                return true;
            }
            if (a === b) {
                feedback.textContent = "Las contraseñas coinciden.";
                feedback.className = "password-match-feedback match-ok";
                confirmPwd.setCustomValidity("");
                return true;
            }
            feedback.textContent = "Las contraseñas no coinciden.";
            feedback.className = "password-match-feedback match-error";
            confirmPwd.setCustomValidity("Las contraseñas no coinciden.");
            return false;
        }

        newPwd.addEventListener("input", updateMatch);
        confirmPwd.addEventListener("input", updateMatch);
        form.addEventListener("submit", function (e) {
            if (!updateMatch()) {
                e.preventDefault();
                confirmPwd.reportValidity();
            }
        });

        return updateMatch;
    }

    function initResetPasswordForm() {
        var form = document.getElementById("reset-password-form");
        if (!form) {
            return;
        }
        if (window.location.search) {
            var params = new URLSearchParams(window.location.search);
            var urlToken = params.get("token");
            if (urlToken) {
                var hiddenToken = form.querySelector('input[type="hidden"][name="token"]');
                if (hiddenToken && !hiddenToken.value) {
                    hiddenToken.value = urlToken;
                }
                if (window.history && typeof window.history.replaceState === "function") {
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
            }
        }
        bindPasswordMatch("reset-password-form", "new_password", "confirm_password", "reset-match-feedback");
    }

    function initRegisterForm() {
        var pwdInput = document.getElementById("password");
        var form = document.getElementById("register-form");
        if (!form || !pwdInput) {
            return;
        }
        var rules = [
            { id: "req-len", test: function (v) { return v.length >= 10; } },
            { id: "req-upper", test: function (v) { return /[A-Z]/.test(v); } },
            { id: "req-lower", test: function (v) { return /[a-z]/.test(v); } },
            { id: "req-digit", test: function (v) { return /\d/.test(v); } },
            { id: "req-symbol", test: function (v) { return /[^A-Za-z0-9\s]/.test(v); } }
        ];

        pwdInput.addEventListener("input", function () {
            var val = pwdInput.value || "";
            rules.forEach(function (rule) {
                var el = document.getElementById(rule.id);
                if (!el) {
                    return;
                }
                if (rule.test(val)) {
                    el.classList.add("policy-ok");
                    el.classList.remove("policy-pending");
                } else {
                    el.classList.remove("policy-ok");
                    el.classList.add("policy-pending");
                }
            });
        });

        bindPasswordMatch("register-form", "password", "confirm_password", "register-match-feedback");
    }

    function initProfileFormsAndModal() {
        bindPasswordMatch("change-password-form", "new_password", "confirm_password", "profile-match-feedback");

        var modal = document.getElementById("delete-account-modal");
        var openBtn = document.getElementById("open-delete-account-modal");
        var closeBtn = document.getElementById("close-delete-account-modal");
        var cancelBtn = document.getElementById("cancel-delete-account-modal");
        var delPwd = document.getElementById("delete_current_password");
        var delWord = document.getElementById("delete_confirmation_word");
        var delSubmit = document.getElementById("confirm-delete-account-btn");
        var delForm = document.getElementById("delete-account-form");

        if (!modal) {
            return;
        }

        function updateDeleteButton() {
            if (!delPwd || !delWord || !delSubmit) {
                return;
            }
            var ok = (delPwd.value || "").length > 0 && (delWord.value || "").trim() === "ELIMINAR";
            delSubmit.disabled = !ok;
        }

        function openModal() {
            if (delForm) {
                delForm.reset();
                restorePasswordTypesInScope(delForm);
            }
            updateDeleteButton();
            if (typeof modal.showModal === "function") {
                modal.showModal();
            } else {
                modal.setAttribute("open", "open");
            }
        }

        function closeModal() {
            if (delForm) {
                delForm.reset();
                restorePasswordTypesInScope(delForm);
            }
            updateDeleteButton();
            if (typeof modal.close === "function") {
                modal.close();
            } else {
                modal.removeAttribute("open");
            }
        }

        if (openBtn) openBtn.addEventListener("click", openModal);
        if (closeBtn) closeBtn.addEventListener("click", closeModal);
        if (cancelBtn) cancelBtn.addEventListener("click", closeModal);
        if (delPwd) delPwd.addEventListener("input", updateDeleteButton);
        if (delWord) delWord.addEventListener("input", updateDeleteButton);
        if (delForm) {
            delForm.addEventListener("submit", function () {
                clearClientStorage();
            });
        }
    }

    function bindLoginAndLogoutForms() {
        var loginForm = document.getElementById("login-form") || document.querySelector('form[action="/auth/login"]');
        if (loginForm && nativeFetch && loginForm.dataset.boundLogin !== "true") {
            loginForm.dataset.boundLogin = "true";
            loginForm.addEventListener("submit", function (event) {
                event.preventDefault();
                restorePasswordTypesInScope(loginForm);
                var formData = new FormData(loginForm);
                var payload = {
                    email: String(formData.get("email") || ""),
                    password: String(formData.get("password") || "")
                };
                clearSensitiveInputs();
                var headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest"
                };
                var csrf = getCsrfToken();
                if (csrf) {
                    headers["X-CSRF-Token"] = csrf;
                }
                nativeFetch(LOGIN_ENDPOINT, {
                    method: "POST",
                    credentials: "same-origin",
                    headers: headers,
                    body: JSON.stringify(payload)
                })
                    .then(function (res) {
                        if (res.ok) {
                            loginForm.reset();
                            window.location.replace("/profile");
                            return;
                        }
                        return res.json().catch(function () {
                            return {};
                        }).then(function (errData) {
                            var msg = (errData && errData.detail) ? String(errData.detail) : "Credenciales inválidas.";
                            window.location.replace("/login?error=" + encodeURIComponent(msg));
                        });
                    })
                    .catch(function () {
                        loginForm.submit();
                    });
            });
        }

        var logoutForm = document.getElementById("logout-form") || document.querySelector('form[action="/auth/logout"]');
        if (logoutForm && nativeFetch && logoutForm.dataset.boundLogout !== "true") {
            logoutForm.dataset.boundLogout = "true";
            logoutForm.addEventListener("submit", function (event) {
                event.preventDefault();
                if (refreshIntervalId !== null) {
                    clearInterval(refreshIntervalId);
                    refreshIntervalId = null;
                }
                clearClientStorage();
                clearSensitiveInputs();
                var headers = {
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest"
                };
                var csrf = getCsrfToken();
                if (csrf) {
                    headers["X-CSRF-Token"] = csrf;
                }
                nativeFetch("/auth/logout", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: headers
                })
                    .finally(function () {
                        clearClientStorage();
                        window.location.replace("/login?logged_out=1");
                    });
            });
        }
    }

    function handlePageShow(event) {
        var navEntries = (window.performance && typeof window.performance.getEntriesByType === "function")
            ? window.performance.getEntriesByType("navigation")
            : [];
        var isBackForward = Boolean(
            (event && event.persisted) ||
            (navEntries && navEntries.length > 0 && navEntries[0].type === "back_forward")
        );
        if (!isBackForward) {
            return;
        }

        clearSensitiveInputs();

        if (!nativeFetch) {
            return;
        }
        var path = window.location.pathname || "";
        var isAuthGate = path === "/login" || path === "/register";
        var isProtectedView = Boolean(
            document.body && document.body.getAttribute("data-authenticated") === "true"
        );
        var mainEl = document.querySelector("main.main-container");

        if (isProtectedView && mainEl) {
            mainEl.style.visibility = "hidden";
        }

        if (isProtectedView || isAuthGate) {
            nativeFetch("/users/me", {
                method: "GET",
                credentials: "same-origin",
                cache: "no-store",
                headers: { "Accept": "application/json" }
            })
                .then(function (res) {
                    if (isProtectedView) {
                        if (res.ok) {
                            if (mainEl) {
                                mainEl.style.visibility = "visible";
                            }
                        } else {
                            clearClientStorage();
                            window.location.replace(LOGIN_EXPIRED_URL);
                        }
                    } else if (isAuthGate && res.ok) {
                        window.location.replace("/profile");
                    }
                })
                .catch(function () {
                    if (isProtectedView) {
                        clearClientStorage();
                        window.location.replace(LOGIN_EXPIRED_URL);
                    }
                });
        }
    }

    function initUiAndSession() {
        initAutoRefreshTimer();
        initPasswordToggles();
        bindPasswordSubmitProtection();
        initResetPasswordForm();
        initRegisterForm();
        initProfileFormsAndModal();
        bindLoginAndLogoutForms();
    }

    window.addEventListener("pageshow", handlePageShow);
    window.addEventListener("pagehide", clearSensitiveInputs);

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initUiAndSession);
    } else {
        initUiAndSession();
    }

    window.AuthSecSession = {
        getCsrfToken: getCsrfToken,
        performSilentRefresh: performSilentRefresh,
        AUTO_REFRESH_INTERVAL_MS: AUTO_REFRESH_INTERVAL_MS
    };
})();
