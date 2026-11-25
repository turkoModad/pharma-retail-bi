/**
 * Centro de Mando Administrativo — Lógica Vanilla JS (Sin CDN, Sin inline scripts, CSP 'self')
 */
(function () {
    "use strict";

    var SVG_NS = "http://www.w3.org/2000/svg";
    var currencyFmt = new Intl.NumberFormat("es-AR", {
        style: "currency",
        currency: "ARS",
        maximumFractionDigits: 2
    });
    var currencyCompactFmt = new Intl.NumberFormat("es-AR", {
        style: "currency",
        currency: "ARS",
        maximumFractionDigits: 0
    });
    var numberFmt = new Intl.NumberFormat("es-AR");

    var state = {
        activeTab: "compras",
        loadedTabs: {},
        compras: {
            groupBy: "year",
            dateFrom: "",
            dateTo: "",
            drillStack: [],
            bounds: { min_date: null, max_date: null },
            lastData: null
        },
        productos: {
            mode: "last_purchase",
            search: "",
            dateFrom: "",
            dateTo: "",
            page: 1
        },
        drogas: {
            selected: "",
            q: ""
        },
        users: {
            search: "",
            role: "",
            isActive: ""
        },
        logs: {
            page: 1,
            eventType: "",
            user: "",
            ip: "",
            dateFrom: "",
            dateTo: ""
        }
    };

    function getCsrfToken() {
        if (window.AuthSecSession && typeof window.AuthSecSession.getCsrfToken === "function") {
            return window.AuthSecSession.getCsrfToken();
        }
        var meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? (meta.getAttribute("content") || "") : "";
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined && text !== null) {
            node.textContent = String(text);
        }
        return node;
    }

    function clearNode(node) {
        if (!node) {
            return;
        }
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    var toastTimer = null;
    function showToast(message, isError) {
        var toast = document.getElementById("admin-toast");
        if (!toast) {
            return;
        }
        toast.textContent = String(message || "");
        toast.classList.toggle("is-error", Boolean(isError));
        toast.hidden = false;
        if (toastTimer) {
            window.clearTimeout(toastTimer);
        }
        toastTimer = window.setTimeout(function () {
            toast.hidden = true;
        }, 3800);
    }

    function apiFetch(url, options) {
        var opts = Object.assign({ credentials: "same-origin" }, options || {});
        var headers = new Headers(opts.headers || {});
        headers.set("Accept", "application/json");
        headers.set("X-Requested-With", "XMLHttpRequest");
        var method = (opts.method || "GET").toUpperCase();
        if (method !== "GET" && method !== "HEAD") {
            var csrf = getCsrfToken();
            if (csrf) {
                headers.set("X-CSRF-Token", csrf);
            }
        }
        opts.headers = headers;
        return fetch(url, opts).then(function (res) {
            if (!res.ok) {
                return res.json().catch(function () {
                    return { detail: "Error HTTP " + res.status };
                }).then(function (err) {
                    var msg = (err && err.detail) ? String(err.detail) : ("Error HTTP " + res.status);
                    throw new Error(msg);
                });
            }
            return res.json();
        });
    }

    function formatShortMoney(val) {
        var n = Number(val || 0);
        if (n >= 1000000) {
            return "$" + (n / 1000000).toFixed(n >= 10000000 ? 0 : 1) + "M";
        }
        if (n >= 1000) {
            return "$" + (n / 1000).toFixed(0) + "K";
        }
        return "$" + n.toFixed(0);
    }

    function formatDateShort(raw) {
        if (!raw) {
            return "—";
        }
        return String(raw).slice(0, 10);
    }

    function formatDateTime(raw) {
        if (!raw) {
            return "—";
        }
        return String(raw).replace("T", " ").slice(0, 19);
    }

    /* ======================================================================
       NAVEGACIÓN ENTRE PESTAÑAS (SIN RECARGAR)
       ====================================================================== */
    function switchTab(tabName) {
        var validTabs = { compras: true, productos: true, users: true, logs: true };
        if (!validTabs[tabName]) {
            tabName = "compras";
        }
        state.activeTab = tabName;

        var buttons = document.querySelectorAll(".admin-nav-tab[data-admin-tab]");
        for (var i = 0; i < buttons.length; i++) {
            var b = buttons[i];
            b.classList.toggle("is-active", b.getAttribute("data-admin-tab") === tabName);
        }

        var panels = document.querySelectorAll(".admin-tab-panel");
        for (var j = 0; j < panels.length; j++) {
            var p = panels[j];
            var isTarget = p.id === "panel-" + tabName;
            p.hidden = !isTarget;
            p.classList.toggle("is-active", isTarget);
        }

        if (window.location.hash !== "#" + tabName && window.history && window.history.replaceState) {
            window.history.replaceState(null, "", "#" + tabName);
        }

        if (!state.loadedTabs[tabName]) {
            state.loadedTabs[tabName] = true;
            if (tabName === "compras") {
                loadCompras();
            } else if (tabName === "productos") {
                loadProductos();
                loadDrogas();
            } else if (tabName === "users") {
                loadUsers();
            } else if (tabName === "logs") {
                loadLogs();
            }
        } else if (tabName === "compras" && state.compras.lastData) {
            renderComprasChart(state.compras.lastData);
        }
    }

    /* ======================================================================
       FASE 4: TABLERO DE COMPRAS ESTILO POWER BI
       ====================================================================== */
    function updateGroupButtons() {
        var btns = document.querySelectorAll(".seg-btn[data-group-by]");
        for (var i = 0; i < btns.length; i++) {
            btns[i].classList.toggle("is-active", btns[i].getAttribute("data-group-by") === state.compras.groupBy);
        }
    }

    function updateDrillControls() {
        var wrap = document.getElementById("compras-drill-controls");
        var btnYear = document.getElementById("btn-drill-up-year");
        var btnMonth = document.getElementById("btn-drill-up-month");
        var badge = document.getElementById("compras-drill-badge");
        if (!wrap) {
            return;
        }
        var stack = state.compras.drillStack;
        if (!stack.length) {
            wrap.hidden = true;
            return;
        }
        wrap.hidden = false;
        btnYear.hidden = false;
        btnMonth.hidden = stack.length < 2;
        if (stack.length === 1) {
            badge.textContent = "Año: " + stack[0].clickedLabel;
        } else {
            badge.textContent = "Mes: " + stack[1].clickedLabel;
        }
    }

    function applyDeltaBadge(node, pct, fallbackText) {
        if (!node) {
            return;
        }
        node.className = "kpi-meta";
        if (pct === null || pct === undefined) {
            node.textContent = fallbackText;
            return;
        }
        var sign = pct >= 0 ? "+" : "";
        node.textContent = sign + pct.toFixed(1) + "% vs. período ant.";
        node.classList.add(pct >= 0 ? "delta-up" : "delta-down");
    }

    function loadCompras() {
        var params = new URLSearchParams();
        params.set("group_by", state.compras.groupBy);
        if (state.compras.dateFrom) {
            params.set("date_from", state.compras.dateFrom);
        }
        if (state.compras.dateTo) {
            params.set("date_to", state.compras.dateTo);
        }

        updateGroupButtons();
        updateDrillControls();

        apiFetch("/api/admin/analytics/compras?" + params.toString())
            .then(function (data) {
                state.compras.lastData = data;
                if (data.bounds) {
                    state.compras.bounds = data.bounds;
                }
                renderComprasKpis(data);
                renderComprasChart(data);
                renderComprasTable(data);
            })
            .catch(function (err) {
                showToast("Error cargando compras: " + err.message, true);
            });
    }

    function renderComprasKpis(data) {
        var k = data.kpis || {};
        var deltas = k.deltas || {};
        document.getElementById("kpi-total-amount").textContent = currencyCompactFmt.format(k.total_amount || 0);
        document.getElementById("kpi-invoice-count").textContent = numberFmt.format(k.invoice_count || 0);
        document.getElementById("kpi-avg-ticket").textContent = currencyCompactFmt.format(k.avg_ticket || 0);
        document.getElementById("kpi-total-units").textContent = numberFmt.format(k.total_units || 0);

        applyDeltaBadge(document.getElementById("kpi-delta-amount"), deltas.total_amount_pct, "Histórico completo");
        applyDeltaBadge(
            document.getElementById("kpi-delta-invoices"),
            deltas.invoice_count_pct,
            "Líneas de ítem: " + numberFmt.format(k.line_count || 0)
        );
        applyDeltaBadge(document.getElementById("kpi-delta-ticket"), deltas.avg_ticket_pct, "Por factura emitida");
        applyDeltaBadge(document.getElementById("kpi-delta-units"), deltas.total_units_pct, "Unidades facturadas");

        var titleMap = {
            year: "Evolución de Compras por Año",
            month: "Evolución de Compras por Mes",
            day: "Evolución de Compras por Día"
        };
        document.getElementById("compras-chart-title").textContent = titleMap[data.group_by] || "Evolución de Compras";
        document.getElementById("compras-period-count").textContent = (data.series ? data.series.length : 0) + " períodos";
    }

    function renderComprasChart(data) {
        var svg = document.getElementById("compras-chart-svg");
        var stage = document.getElementById("compras-chart-stage");
        var tooltip = document.getElementById("compras-chart-tooltip");
        if (!svg || !stage) {
            return;
        }
        clearNode(svg);
        if (tooltip) {
            tooltip.hidden = true;
        }

        var series = data.series || [];
        var width = Math.max(360, stage.clientWidth || 880);
        var height = 265;
        svg.setAttribute("viewBox", "0 0 " + width + " " + height);

        if (!series.length) {
            var emptyTxt = document.createElementNS(SVG_NS, "text");
            emptyTxt.setAttribute("x", String(width / 2));
            emptyTxt.setAttribute("y", String(height / 2));
            emptyTxt.setAttribute("text-anchor", "middle");
            emptyTxt.setAttribute("class", "svg-axis-label");
            emptyTxt.textContent = "No hay compras registradas en el rango seleccionado.";
            svg.appendChild(emptyTxt);
            return;
        }

        var padLeft = 64;
        var padRight = 16;
        var padTop = 18;
        var padBottom = 36;
        var plotW = width - padLeft - padRight;
        var plotH = height - padTop - padBottom;

        var maxVal = 0;
        for (var i = 0; i < series.length; i++) {
            if (series[i].total_amount > maxVal) {
                maxVal = series[i].total_amount;
            }
        }
        if (maxVal <= 0) {
            maxVal = 1;
        }
        maxVal = maxVal * 1.08;

        // Líneas guía horizontales
        var ticks = 4;
        for (var t = 0; t <= ticks; t++) {
            var ratio = t / ticks;
            var yPos = padTop + plotH - ratio * plotH;
            var line = document.createElementNS(SVG_NS, "line");
            line.setAttribute("x1", String(padLeft));
            line.setAttribute("x2", String(width - padRight));
            line.setAttribute("y1", yPos.toFixed(1));
            line.setAttribute("y2", yPos.toFixed(1));
            line.setAttribute("class", t === 0 ? "svg-axis-line" : "svg-grid-line");
            svg.appendChild(line);

            var lbl = document.createElementNS(SVG_NS, "text");
            lbl.setAttribute("x", String(padLeft - 8));
            lbl.setAttribute("y", (yPos + 4).toFixed(1));
            lbl.setAttribute("text-anchor", "end");
            lbl.setAttribute("class", "svg-axis-label");
            lbl.textContent = formatShortMoney(maxVal * ratio);
            svg.appendChild(lbl);
        }

        var n = series.length;
        var slotW = plotW / n;
        var barW = Math.max(2, Math.min(54, slotW * 0.68));
        var maxLabels = Math.max(4, Math.floor(plotW / 58));
        var labelStep = Math.max(1, Math.ceil(n / maxLabels));

        series.forEach(function (item, idx) {
            var barH = Math.max(2, (item.total_amount / maxVal) * plotH);
            var xCenter = padLeft + idx * slotW + slotW / 2;
            var xBar = xCenter - barW / 2;
            var yBar = padTop + plotH - barH;

            var rect = document.createElementNS(SVG_NS, "rect");
            rect.setAttribute("x", xBar.toFixed(1));
            rect.setAttribute("y", yBar.toFixed(1));
            rect.setAttribute("width", barW.toFixed(1));
            rect.setAttribute("height", barH.toFixed(1));
            rect.setAttribute("rx", barW > 8 ? "3" : "1");
            rect.setAttribute("class", "svg-bar");
            svg.appendChild(rect);

            // Zona táctil/hover completa por columna
            var hit = document.createElementNS(SVG_NS, "rect");
            hit.setAttribute("x", (padLeft + idx * slotW).toFixed(1));
            hit.setAttribute("y", String(padTop));
            hit.setAttribute("width", slotW.toFixed(1));
            hit.setAttribute("height", String(plotH));
            hit.setAttribute("class", "svg-bar-hit");
            svg.appendChild(hit);

            if (idx % labelStep === 0 || idx === n - 1) {
                var xTxt = document.createElementNS(SVG_NS, "text");
                xTxt.setAttribute("x", xCenter.toFixed(1));
                xTxt.setAttribute("y", String(padTop + plotH + 18));
                xTxt.setAttribute("text-anchor", "middle");
                xTxt.setAttribute("class", "svg-axis-label");
                xTxt.textContent = item.label;
                svg.appendChild(xTxt);
            }

            function positionTooltip(evt) {
                if (!tooltip) {
                    return;
                }
                clearNode(tooltip);
                var titleEl = el("strong", "", item.label);
                var line1 = el("div", "", "Monto: " + currencyFmt.format(item.total_amount));
                var line2 = el(
                    "div",
                    "",
                    numberFmt.format(item.invoice_count) + " facturas · " + numberFmt.format(item.total_units) + " u."
                );
                tooltip.appendChild(titleEl);
                tooltip.appendChild(line1);
                tooltip.appendChild(line2);
                tooltip.hidden = false;

                var stageRect = stage.getBoundingClientRect();
                var relX = evt.clientX - stageRect.left + 12;
                var relY = evt.clientY - stageRect.top - 10;
                if (relX + 200 > stageRect.width) {
                    relX = Math.max(8, relX - 210);
                }
                if (relY < 4) {
                    relY = 4;
                }
                tooltip.style.left = relX + "px";
                tooltip.style.top = relY + "px";
            }

            hit.addEventListener("mouseenter", function (evt) {
                rect.classList.add("is-hovered");
                positionTooltip(evt);
            });
            hit.addEventListener("mousemove", positionTooltip);
            hit.addEventListener("mouseleave", function () {
                rect.classList.remove("is-hovered");
                if (tooltip) {
                    tooltip.hidden = true;
                }
            });

            hit.addEventListener("click", function () {
                handleComprasDrillDown(data.group_by, item);
            });
        });
    }

    function handleComprasDrillDown(currentGroup, item) {
        if (currentGroup === "year" && /^\d{4}$/.test(item.period)) {
            state.compras.drillStack.push({
                groupBy: state.compras.groupBy,
                dateFrom: state.compras.dateFrom,
                dateTo: state.compras.dateTo,
                clickedLabel: item.period
            });
            state.compras.groupBy = "month";
            state.compras.dateFrom = item.period + "-01-01";
            state.compras.dateTo = item.period + "-12-31";
            document.getElementById("compras-date-from").value = state.compras.dateFrom;
            document.getElementById("compras-date-to").value = state.compras.dateTo;
            loadCompras();
        } else if (currentGroup === "month" && /^\d{4}-\d{2}$/.test(item.period)) {
            var parts = item.period.split("-");
            var yr = parseInt(parts[0], 10);
            var mo = parseInt(parts[1], 10);
            var lastDay = new Date(yr, mo, 0).getDate();
            var dd = lastDay < 10 ? "0" + lastDay : String(lastDay);

            state.compras.drillStack.push({
                groupBy: state.compras.groupBy,
                dateFrom: state.compras.dateFrom,
                dateTo: state.compras.dateTo,
                clickedLabel: item.label
            });
            state.compras.groupBy = "day";
            state.compras.dateFrom = item.period + "-01";
            state.compras.dateTo = item.period + "-" + dd;
            document.getElementById("compras-date-from").value = state.compras.dateFrom;
            document.getElementById("compras-date-to").value = state.compras.dateTo;
            loadCompras();
        }
    }

    function renderComprasTable(data) {
        var tbody = document.getElementById("compras-series-tbody");
        if (!tbody) {
            return;
        }
        clearNode(tbody);
        var series = data.series || [];
        if (!series.length) {
            var trEmpty = el("tr");
            var tdEmpty = el("td", "empty-row", "Sin registros para este intervalo.");
            tdEmpty.colSpan = 6;
            trEmpty.appendChild(tdEmpty);
            tbody.appendChild(trEmpty);
            return;
        }
        for (var i = series.length - 1; i >= 0; i--) {
            var row = series[i];
            var tr = el("tr");
            tr.appendChild(el("td", "mono-text", row.label));
            tr.appendChild(el("td", "num-col", numberFmt.format(row.invoice_count)));
            tr.appendChild(el("td", "num-col", numberFmt.format(row.line_count)));
            tr.appendChild(el("td", "num-col", numberFmt.format(row.total_units)));
            tr.appendChild(el("td", "num-col", currencyCompactFmt.format(row.avg_ticket)));
            tr.appendChild(el("td", "num-col", currencyFmt.format(row.total_amount)));
            tbody.appendChild(tr);
        }
    }

    /* ======================================================================
       FASE 5: PRODUCTOS Y COMPARADOR DE DROGAS
       ====================================================================== */
    function updateProdModeButtons() {
        var btns = document.querySelectorAll(".seg-btn[data-prod-mode]");
        for (var i = 0; i < btns.length; i++) {
            btns[i].classList.toggle("is-active", btns[i].getAttribute("data-prod-mode") === state.productos.mode);
        }
    }

    function loadProductos() {
        var params = new URLSearchParams();
        params.set("mode", state.productos.mode);
        params.set("page", String(state.productos.page));
        params.set("page_size", "20");
        if (state.productos.search) {
            params.set("search", state.productos.search);
        }
        if (state.productos.dateFrom) {
            params.set("date_from", state.productos.dateFrom);
        }
        if (state.productos.dateTo) {
            params.set("date_to", state.productos.dateTo);
        }
        updateProdModeButtons();

        apiFetch("/api/admin/analytics/productos?" + params.toString())
            .then(function (data) {
                renderProductosTable(data);
                renderPagination("prod-pagination", data.page, data.total_pages, data.total, function (nextPage) {
                    state.productos.page = nextPage;
                    loadProductos();
                });
            })
            .catch(function (err) {
                showToast("Error cargando productos: " + err.message, true);
            });
    }

    function renderProductosTable(data) {
        var tbody = document.getElementById("prod-tbody");
        clearNode(tbody);
        var items = data.items || [];
        if (!items.length) {
            var trEmpty = el("tr");
            var tdEmpty = el("td", "empty-row", "No se encontraron productos con los filtros actuales.");
            tdEmpty.colSpan = 6;
            trEmpty.appendChild(tdEmpty);
            tbody.appendChild(trEmpty);
            return;
        }
        var maxUnits = Math.max(1, data.max_units || 1);

        items.forEach(function (item) {
            var tr = el("tr");
            tr.appendChild(el("td", "mono-text", item.codigo));

            var tdDesc = el("td");
            tdDesc.appendChild(el("strong", "", item.nombre));
            if (item.droga) {
                tdDesc.appendChild(document.createElement("br"));
                var drugLink = el("small", "mono-text", item.droga);
                tdDesc.appendChild(drugLink);
            }
            tr.appendChild(tdDesc);

            var tdLab = el("td");
            tdLab.appendChild(el("span", "", item.laboratorio || "—"));
            if (item.presentacion) {
                tdLab.appendChild(document.createElement("br"));
                tdLab.appendChild(el("small", "muted-uuid", item.presentacion));
            }
            tr.appendChild(tdLab);

            tr.appendChild(el("td", "num-col", currencyFmt.format(item.last_price)));
            tr.appendChild(el("td", "mono-text nowrap-cell", formatDateShort(item.last_fecha)));

            var tdVol = el("td", "num-col");
            tdVol.appendChild(el("strong", "", numberFmt.format(item.total_units) + " u."));
            tdVol.appendChild(el("small", "muted-uuid", " (" + item.purchase_count + " compras)"));
            if (data.mode === "most_purchased") {
                var track = el("div", "prop-bar-track");
                var fill = el("div", "prop-bar-fill");
                var pct = Math.max(4, Math.min(100, Math.round((item.total_units / maxUnits) * 100)));
                fill.style.width = pct + "%";
                track.appendChild(fill);
                tdVol.appendChild(track);
            }
            tr.appendChild(tdVol);
            tbody.appendChild(tr);
        });
    }

    function loadDrogas() {
        var params = new URLSearchParams();
        if (state.drogas.selected) {
            params.set("droga", state.drogas.selected);
        }
        if (state.drogas.q) {
            params.set("q", state.drogas.q);
        }
        var dFrom = document.getElementById("droga-date-from").value;
        var dTo = document.getElementById("droga-date-to").value;
        if (dFrom) {
            params.set("date_from", dFrom);
        }
        if (dTo) {
            params.set("date_to", dTo);
        }

        apiFetch("/api/admin/analytics/drogas?" + params.toString())
            .then(function (data) {
                renderDrugSuggestions(data.suggestions || []);
                renderDrugComparison(data);
            })
            .catch(function (err) {
                showToast("Error comparando drogas: " + err.message, true);
            });
    }

    function renderDrugSuggestions(suggestions) {
        var wrap = document.getElementById("droga-suggestions");
        clearNode(wrap);
        suggestions.forEach(function (s) {
            var btn = el(
                "button",
                "drug-chip" + (state.drogas.selected === s.droga ? " is-active" : ""),
                s.droga + " (" + s.lab_count + " marcas)"
            );
            btn.type = "button";
            btn.addEventListener("click", function () {
                state.drogas.selected = s.droga;
                document.getElementById("droga-search").value = s.droga;
                loadDrogas();
            });
            wrap.appendChild(btn);
        });
    }

    function renderDrugComparison(data) {
        var tbody = document.getElementById("droga-tbody");
        var badge = document.getElementById("droga-selected-badge");
        clearNode(tbody);

        if (!data.droga) {
            badge.hidden = true;
            var trHint = el("tr");
            var tdHint = el("td", "empty-row", "Busque o haga clic en una droga sugerida para comparar precios entre marcas.");
            tdHint.colSpan = 6;
            trHint.appendChild(tdHint);
            tbody.appendChild(trHint);
            return;
        }

        badge.hidden = false;
        badge.textContent = data.droga + " · " + (data.items ? data.items.length : 0) + " presentaciones";

        var items = data.items || [];
        if (!items.length) {
            var trEmpty = el("tr");
            var tdEmpty = el("td", "empty-row", "No se encontraron compras para la droga seleccionada.");
            tdEmpty.colSpan = 6;
            trEmpty.appendChild(tdEmpty);
            tbody.appendChild(trEmpty);
            return;
        }

        var maxGap = 1;
        items.forEach(function (it) {
            if (it.diff_pct > maxGap) {
                maxGap = it.diff_pct;
            }
        });

        items.forEach(function (it) {
            var tr = el("tr", it.is_cheapest ? "cheapest-row" : "");

            var tdBrand = el("td");
            tdBrand.appendChild(el("strong", "", it.laboratorio || "Sin laboratorio"));
            tdBrand.appendChild(document.createElement("br"));
            tdBrand.appendChild(el("small", "", it.nombre));
            if (it.presentacion) {
                tdBrand.appendChild(document.createElement("br"));
                tdBrand.appendChild(el("small", "muted-uuid", it.presentacion));
            }
            tr.appendChild(tdBrand);

            tr.appendChild(el("td", "mono-text", it.codigo));

            var tdPrice = el("td", "num-col");
            tdPrice.appendChild(el("strong", "", currencyFmt.format(it.last_price)));
            if (it.is_cheapest) {
                tdPrice.appendChild(document.createElement("br"));
                tdPrice.appendChild(el("span", "badge badge-cheapest", "Más económica"));
            }
            tr.appendChild(tdPrice);

            var tdHist = el("td", "num-col");
            tdHist.appendChild(el("span", "mono-text", currencyCompactFmt.format(it.min_price) + " / " + currencyCompactFmt.format(it.max_price)));
            tr.appendChild(tdHist);

            var tdGap = el("td");
            if (it.is_cheapest) {
                tdGap.appendChild(el("span", "badge badge-verified", "Referencia (0%)"));
            } else {
                tdGap.appendChild(el("span", "mono-text", "+" + it.diff_pct.toFixed(1) + "%"));
                var track = el("div", "prop-bar-track");
                var fill = el("div", "gap-bar-fill");
                var w = Math.max(4, Math.min(100, Math.round((it.diff_pct / maxGap) * 100)));
                fill.style.width = w + "%";
                track.appendChild(fill);
                tdGap.appendChild(track);
            }
            tr.appendChild(tdGap);

            tr.appendChild(el("td", "mono-text nowrap-cell", formatDateShort(it.last_fecha)));
            tbody.appendChild(tr);
        });
    }

    /* ======================================================================
       FASE 2: ADMINISTRACIÓN DE USUARIOS
       ====================================================================== */
    function loadUsers() {
        var params = new URLSearchParams();
        if (state.users.search) {
            params.set("search", state.users.search);
        }
        if (state.users.role) {
            params.set("role", state.users.role);
        }
        if (state.users.isActive) {
            params.set("is_active", state.users.isActive);
        }

        apiFetch("/api/admin/users/overview?" + params.toString())
            .then(function (data) {
                var s = data.summary || {};
                document.getElementById("users-sum-total").textContent = numberFmt.format(s.total || 0);
                document.getElementById("users-sum-admins").textContent = numberFmt.format(s.admins || 0);
                document.getElementById("users-sum-active").textContent = numberFmt.format(s.active || 0);
                document.getElementById("users-sum-disabled").textContent = numberFmt.format(s.disabled || 0);
                renderUsersTable(data.users || []);
            })
            .catch(function (err) {
                showToast("Error cargando usuarios: " + err.message, true);
            });
    }

    function renderUsersTable(users) {
        var tbody = document.getElementById("users-tbody");
        clearNode(tbody);
        if (!users.length) {
            var trEmpty = el("tr");
            var tdEmpty = el("td", "empty-row", "No hay usuarios que coincidan con el filtro.");
            tdEmpty.colSpan = 5;
            trEmpty.appendChild(tdEmpty);
            tbody.appendChild(trEmpty);
            return;
        }

        users.forEach(function (u) {
            var tr = el("tr");

            var tdInfo = el("td");
            tdInfo.appendChild(el("strong", "", u.full_name || "Sin nombre"));
            tdInfo.appendChild(document.createElement("br"));
            tdInfo.appendChild(el("small", "mono-text", u.email));
            tdInfo.appendChild(document.createElement("br"));
            tdInfo.appendChild(el("small", "muted-uuid", "ID: " + u.id));
            tr.appendChild(tdInfo);

            var tdRole = el("td");
            var roleLower = String(u.role || "user").toLowerCase();
            tdRole.appendChild(el("span", "badge " + (roleLower === "admin" ? "badge-admin" : "badge-user"), roleLower.toUpperCase()));
            tr.appendChild(tdRole);

            var tdStatus = el("td");
            tdStatus.appendChild(el("span", "badge " + (u.is_active ? "badge-verified" : "badge-danger"), u.is_active ? "ACTIVO" : "DESHABILITADO"));
            tdStatus.appendChild(el("small", u.is_verified ? "verified-tag" : "unverified-tag", u.is_verified ? "✓ Verificado" : "⚠ No verificado"));
            tr.appendChild(tdStatus);

            var tdSec = el("td");
            tdSec.appendChild(el("span", "mono-text", "Fallos: " + (u.failed_login_attempts || 0)));
            if (u.locked_until) {
                tdSec.appendChild(document.createElement("br"));
                tdSec.appendChild(el("span", "badge badge-danger", "BLOQUEADO"));
            }
            tr.appendChild(tdSec);

            var tdAct = el("td", "actions-cell");
            var grp = el("div", "action-buttons-group");

            var btnStatus = el("button", "btn-xs " + (u.is_active ? "contrast outline" : "primary"), u.is_active ? "Suspender" : "Activar");
            btnStatus.type = "button";
            btnStatus.addEventListener("click", function () {
                mutateUser("/api/admin/users/" + u.id + "/status", { is_active: !u.is_active }, "Estado actualizado.");
            });
            grp.appendChild(btnStatus);

            var btnEmail = el("button", "btn-xs secondary outline", "Cambiar Email");
            btnEmail.type = "button";
            btnEmail.addEventListener("click", function () {
                openEmailModal(u);
            });
            grp.appendChild(btnEmail);

            var nextRole = roleLower === "admin" ? "user" : "admin";
            var btnRole = el("button", "btn-xs secondary outline", "Rol → " + nextRole.toUpperCase());
            btnRole.type = "button";
            btnRole.addEventListener("click", function () {
                mutateUser("/api/admin/users/" + u.id + "/role", { role: nextRole }, "Rol actualizado a " + nextRole.toUpperCase() + ".");
            });
            grp.appendChild(btnRole);

            if (!u.is_verified) {
                var btnVerify = el("button", "btn-xs primary", "Verificar Email");
                btnVerify.type = "button";
                btnVerify.addEventListener("click", function () {
                    mutateUser("/api/admin/users/" + u.id + "/verify", { is_verified: true }, "Usuario verificado manualmente.");
                });
                grp.appendChild(btnVerify);
            }

            if (u.locked_until || (u.failed_login_attempts && u.failed_login_attempts > 0)) {
                var btnUnlock = el("button", "btn-xs warning-btn", "Desbloquear");
                btnUnlock.type = "button";
                btnUnlock.addEventListener("click", function () {
                    mutateUser("/api/admin/users/" + u.id + "/unlock", { unlock_account: true }, "Cuenta desbloqueada.");
                });
                grp.appendChild(btnUnlock);
            }

            tdAct.appendChild(grp);
            tr.appendChild(tdAct);
            tbody.appendChild(tr);
        });
    }

    function mutateUser(url, payload, successMsg) {
        apiFetch(url, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        })
            .then(function () {
                showToast(successMsg, false);
                loadUsers();
                if (state.loadedTabs.logs) {
                    loadLogs();
                }
            })
            .catch(function (err) {
                showToast(err.message, true);
            });
    }

    function openEmailModal(user) {
        var modal = document.getElementById("edit-email-modal");
        var errBox = document.getElementById("edit-email-error");
        document.getElementById("edit-email-user-id").value = user.id;
        document.getElementById("edit-email-user-name").textContent = user.full_name || "Usuario";
        document.getElementById("edit-email-current").textContent = user.email;
        document.getElementById("edit-email-input").value = user.email;
        errBox.hidden = true;
        errBox.textContent = "";
        if (typeof modal.showModal === "function") {
            modal.showModal();
        } else {
            modal.setAttribute("open", "open");
        }
    }

    function closeEmailModal() {
        var modal = document.getElementById("edit-email-modal");
        if (typeof modal.close === "function") {
            modal.close();
        } else {
            modal.removeAttribute("open");
        }
    }

    /* ======================================================================
       FASE 3: VISOR FORENSE DE LOGS DE AUDITORÍA
       ====================================================================== */
    function loadLogs() {
        var params = new URLSearchParams();
        params.set("page", String(state.logs.page));
        params.set("page_size", "25");
        if (state.logs.eventType) {
            params.set("event_type", state.logs.eventType);
        }
        if (state.logs.user) {
            params.set("user", state.logs.user);
        }
        if (state.logs.ip) {
            params.set("ip", state.logs.ip);
        }
        if (state.logs.dateFrom) {
            params.set("date_from", state.logs.dateFrom);
        }
        if (state.logs.dateTo) {
            params.set("date_to", state.logs.dateTo);
        }

        apiFetch("/api/admin/logs?" + params.toString())
            .then(function (data) {
                document.getElementById("logs-total-badge").textContent = numberFmt.format(data.total || 0) + " registros";
                renderLogsTable(data.items || []);
                renderPagination("logs-pagination", data.page, data.total_pages, data.total, function (nextPage) {
                    state.logs.page = nextPage;
                    loadLogs();
                });
            })
            .catch(function (err) {
                showToast("Error cargando logs: " + err.message, true);
            });
    }

    function getSeverityClass(evType) {
        if (/FAILED|LOCKED|REUSE|DELETED/.test(evType)) {
            return "badge-danger";
        }
        if (/ADMIN_ACTION|PASSWORD_RESET/.test(evType)) {
            return "badge-warn";
        }
        if (/SUCCESS|VERIFIED|REGISTER/.test(evType)) {
            return "badge-verified";
        }
        return "";
    }

    function renderLogsTable(items) {
        var tbody = document.getElementById("logs-tbody");
        clearNode(tbody);
        if (!items.length) {
            var trEmpty = el("tr");
            var tdEmpty = el("td", "empty-row", "No se encontraron registros de auditoría.");
            tdEmpty.colSpan = 5;
            trEmpty.appendChild(tdEmpty);
            tbody.appendChild(trEmpty);
            return;
        }

        items.forEach(function (log) {
            var tr = el("tr");
            tr.appendChild(el("td", "mono-text nowrap-cell", formatDateTime(log.created_at) + " UTC"));

            var tdEv = el("td");
            var sevClass = getSeverityClass(log.event_type || "");
            tdEv.appendChild(el("span", "badge event-badge " + sevClass, log.event_type));
            tr.appendChild(tdEv);

            var tdUser = el("td");
            if (log.user_email) {
                tdUser.appendChild(el("strong", "", log.user_name || "Usuario"));
                tdUser.appendChild(document.createElement("br"));
                tdUser.appendChild(el("small", "mono-text", log.user_email));
            } else {
                tdUser.appendChild(el("span", "mono-text", log.user_id ? String(log.user_id) : "Sistema"));
            }
            tr.appendChild(tdUser);

            tr.appendChild(el("td", "mono-text", log.ip_address || "N/A"));

            var tdDet = el("td", "details-cell");
            tdDet.appendChild(el("code", "", JSON.stringify(log.details || {})));
            tr.appendChild(tdDet);

            tbody.appendChild(tr);
        });
    }

    /* ======================================================================
       PAGINACIÓN REUTILIZABLE
       ====================================================================== */
    function renderPagination(containerId, page, totalPages, totalItems, onPageChange) {
        var bar = document.getElementById(containerId);
        if (!bar) {
            return;
        }
        clearNode(bar);
        bar.appendChild(el("span", "", "Página " + page + " de " + totalPages + " (" + numberFmt.format(totalItems || 0) + " registros)"));

        var btns = el("div", "pagination-btns");
        var prevBtn = el("button", "btn-xs secondary outline", "← Anterior");
        prevBtn.type = "button";
        prevBtn.disabled = page <= 1;
        prevBtn.addEventListener("click", function () {
            if (page > 1) {
                onPageChange(page - 1);
            }
        });

        var nextBtn = el("button", "btn-xs secondary outline", "Siguiente →");
        nextBtn.type = "button";
        nextBtn.disabled = page >= totalPages;
        nextBtn.addEventListener("click", function () {
            if (page < totalPages) {
                onPageChange(page + 1);
            }
        });

        btns.appendChild(prevBtn);
        btns.appendChild(nextBtn);
        bar.appendChild(btns);
    }

    /* ======================================================================
       INICIALIZACIÓN Y EVENTOS
       ====================================================================== */
    function bindEvents() {
        var tabBtns = document.querySelectorAll(".admin-nav-tab[data-admin-tab]");
        for (var i = 0; i < tabBtns.length; i++) {
            tabBtns[i].addEventListener("click", function () {
                switchTab(this.getAttribute("data-admin-tab"));
            });
        }

        // Compras slicers
        var groupBtns = document.querySelectorAll(".seg-btn[data-group-by]");
        for (var j = 0; j < groupBtns.length; j++) {
            groupBtns[j].addEventListener("click", function () {
                state.compras.groupBy = this.getAttribute("data-group-by");
                state.compras.drillStack = [];
                loadCompras();
            });
        }

        document.getElementById("btn-compras-apply").addEventListener("click", function () {
            state.compras.dateFrom = document.getElementById("compras-date-from").value;
            state.compras.dateTo = document.getElementById("compras-date-to").value;
            state.compras.drillStack = [];
            loadCompras();
        });

        var presetBtns = document.querySelectorAll("[data-preset]");
        for (var k = 0; k < presetBtns.length; k++) {
            presetBtns[k].addEventListener("click", function () {
                var preset = this.getAttribute("data-preset");
                state.compras.drillStack = [];
                if (preset === "all") {
                    state.compras.dateFrom = "";
                    state.compras.dateTo = "";
                    state.compras.groupBy = "year";
                } else if (preset === "this_year") {
                    var refYear = state.compras.bounds.max_date
                        ? state.compras.bounds.max_date.slice(0, 4)
                        : String(new Date().getFullYear());
                    state.compras.dateFrom = refYear + "-01-01";
                    state.compras.dateTo = refYear + "-12-31";
                    state.compras.groupBy = "month";
                } else if (preset === "last_30") {
                    var anchorStr = state.compras.bounds.max_date || new Date().toISOString().slice(0, 10);
                    var anchor = new Date(anchorStr + "T00:00:00Z");
                    var start = new Date(anchor.getTime() - 29 * 86400000);
                    state.compras.dateFrom = start.toISOString().slice(0, 10);
                    state.compras.dateTo = anchor.toISOString().slice(0, 10);
                    state.compras.groupBy = "day";
                }
                document.getElementById("compras-date-from").value = state.compras.dateFrom;
                document.getElementById("compras-date-to").value = state.compras.dateTo;
                loadCompras();
            });
        }

        document.getElementById("btn-drill-up-year").addEventListener("click", function () {
            if (!state.compras.drillStack.length) {
                return;
            }
            var root = state.compras.drillStack[0];
            state.compras.drillStack = [];
            state.compras.groupBy = root.groupBy;
            state.compras.dateFrom = root.dateFrom;
            state.compras.dateTo = root.dateTo;
            document.getElementById("compras-date-from").value = root.dateFrom;
            document.getElementById("compras-date-to").value = root.dateTo;
            loadCompras();
        });

        document.getElementById("btn-drill-up-month").addEventListener("click", function () {
            if (state.compras.drillStack.length < 2) {
                return;
            }
            var prev = state.compras.drillStack.pop();
            state.compras.groupBy = prev.groupBy;
            state.compras.dateFrom = prev.dateFrom;
            state.compras.dateTo = prev.dateTo;
            document.getElementById("compras-date-from").value = prev.dateFrom;
            document.getElementById("compras-date-to").value = prev.dateTo;
            loadCompras();
        });

        // Productos explorer
        var prodModeBtns = document.querySelectorAll(".seg-btn[data-prod-mode]");
        for (var m = 0; m < prodModeBtns.length; m++) {
            prodModeBtns[m].addEventListener("click", function () {
                state.productos.mode = this.getAttribute("data-prod-mode");
                state.productos.page = 1;
                loadProductos();
            });
        }

        var prodTimer = null;
        document.getElementById("prod-search").addEventListener("input", function () {
            var val = this.value;
            window.clearTimeout(prodTimer);
            prodTimer = window.setTimeout(function () {
                state.productos.search = val.trim();
                state.productos.page = 1;
                loadProductos();
            }, 260);
        });

        document.getElementById("btn-prod-search").addEventListener("click", function () {
            state.productos.search = document.getElementById("prod-search").value.trim();
            state.productos.dateFrom = document.getElementById("prod-date-from").value;
            state.productos.dateTo = document.getElementById("prod-date-to").value;
            state.productos.page = 1;
            loadProductos();
        });

        document.getElementById("btn-prod-clear").addEventListener("click", function () {
            document.getElementById("prod-search").value = "";
            document.getElementById("prod-date-from").value = "";
            document.getElementById("prod-date-to").value = "";
            state.productos.search = "";
            state.productos.dateFrom = "";
            state.productos.dateTo = "";
            state.productos.page = 1;
            loadProductos();
        });

        // Comparador de drogas
        var drogaTimer = null;
        document.getElementById("droga-search").addEventListener("input", function () {
            var val = this.value;
            window.clearTimeout(drogaTimer);
            drogaTimer = window.setTimeout(function () {
                state.drogas.q = val.trim();
                state.drogas.selected = "";
                loadDrogas();
            }, 240);
        });

        document.getElementById("droga-search").addEventListener("keydown", function (evt) {
            if (evt.key === "Enter") {
                evt.preventDefault();
                state.drogas.selected = this.value.trim();
                state.drogas.q = this.value.trim();
                loadDrogas();
            }
        });

        document.getElementById("btn-droga-search").addEventListener("click", function () {
            var val = document.getElementById("droga-search").value.trim();
            state.drogas.selected = val;
            state.drogas.q = val;
            loadDrogas();
        });

        // Usuarios
        var userTimer = null;
        document.getElementById("users-search").addEventListener("input", function () {
            var val = this.value;
            window.clearTimeout(userTimer);
            userTimer = window.setTimeout(function () {
                state.users.search = val.trim();
                loadUsers();
            }, 220);
        });

        document.getElementById("users-role-filter").addEventListener("change", function () {
            state.users.role = this.value;
            loadUsers();
        });

        document.getElementById("users-status-filter").addEventListener("change", function () {
            state.users.isActive = this.value;
            loadUsers();
        });

        document.getElementById("btn-users-refresh").addEventListener("click", loadUsers);

        // Modal email
        document.getElementById("close-edit-email-modal").addEventListener("click", closeEmailModal);
        document.getElementById("cancel-edit-email-modal").addEventListener("click", closeEmailModal);
        document.getElementById("edit-email-form").addEventListener("submit", function (evt) {
            evt.preventDefault();
            var uid = document.getElementById("edit-email-user-id").value;
            var newEmail = document.getElementById("edit-email-input").value.trim();
            var errBox = document.getElementById("edit-email-error");
            errBox.hidden = true;

            apiFetch("/api/admin/users/" + uid + "/email", {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: newEmail })
            })
                .then(function () {
                    closeEmailModal();
                    showToast("Correo electrónico actualizado correctamente.", false);
                    loadUsers();
                    if (state.loadedTabs.logs) {
                        loadLogs();
                    }
                })
                .catch(function (err) {
                    errBox.textContent = err.message;
                    errBox.hidden = false;
                });
        });

        // Logs
        document.getElementById("btn-logs-filter").addEventListener("click", function () {
            state.logs.eventType = document.getElementById("logs-event-type").value;
            state.logs.user = document.getElementById("logs-user").value.trim();
            state.logs.ip = document.getElementById("logs-ip").value.trim();
            state.logs.dateFrom = document.getElementById("logs-date-from").value;
            state.logs.dateTo = document.getElementById("logs-date-to").value;
            state.logs.page = 1;
            loadLogs();
        });

        document.getElementById("btn-logs-clear").addEventListener("click", function () {
            document.getElementById("logs-event-type").value = "";
            document.getElementById("logs-user").value = "";
            document.getElementById("logs-ip").value = "";
            document.getElementById("logs-date-from").value = "";
            document.getElementById("logs-date-to").value = "";
            state.logs.eventType = "";
            state.logs.user = "";
            state.logs.ip = "";
            state.logs.dateFrom = "";
            state.logs.dateTo = "";
            state.logs.page = 1;
            loadLogs();
        });

        var resizeTimer = null;
        window.addEventListener("resize", function () {
            window.clearTimeout(resizeTimer);
            resizeTimer = window.setTimeout(function () {
                if (state.activeTab === "compras" && state.compras.lastData) {
                    renderComprasChart(state.compras.lastData);
                }
            }, 150);
        });
    }

    function init() {
        if (!document.getElementById("panel-compras")) {
            return;
        }
        bindEvents();
        var hash = (window.location.hash || "").replace("#", "").toLowerCase();
        switchTab(hash || "compras");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
