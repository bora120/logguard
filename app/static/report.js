/* LogGuard 보고서 화면: 그래프, 위험도 필터, 할 일 체크, CSV 저장, 인쇄 */
(function () {
  "use strict";

  const dataEl = document.getElementById("report-data");
  if (!dataEl) return;
  const data = JSON.parse(dataEl.textContent);

  const COLOR = {
    suspicious: "#E0475E",
    other: "#DADDE3",
    bar: "#E58CAD",
    barHover: "#C2456F",
    grid: "#EEECF1",
    tick: "#6B6573",
    label: "#4E4956",
    level: { "높음": "#E0475E", "중간": "#E8913F", "낮음": "#7C8BDB" },
  };
  const LEVEL_NAME = { "높음": "위험", "중간": "주의", "낮음": "참고" };
  const EASY = {};
  const story = data.story || {};
  (story.by_rule || []).forEach(function (x) { EASY[x.rule] = x.easy; });

  const pad = function (n) { return String(n).padStart(2, "0"); };
  const tzOffsetMs = (data.summary.tz_offset_min || 0) * 60e3;
  const narrow = window.matchMedia("(max-width: 640px)").matches;

  /* ── 그래프 ─────────────────────────────────────────────── */
  function setupCharts() {
    if (!window.Chart) return;
    const C = window.Chart;
    C.defaults.font.family = getComputedStyle(document.body).fontFamily;
    C.defaults.font.size = 12.5;
    C.defaults.font.weight = "normal";
    C.defaults.color = COLOR.tick;
    C.defaults.animation = false;
    C.defaults.maintainAspectRatio = false;
    Object.assign(C.defaults.plugins.tooltip, {
      backgroundColor: "#25222A", padding: 10, cornerRadius: 8, boxPadding: 4,
      titleFont: { weight: "normal", size: 14 }, bodyFont: { weight: "normal", size: 13 },
    });
    C.defaults.plugins.legend.display = false;   // 범례는 HTML로 그린다

    timelineChart(C);
    rulesChart(C);
    ganttChart(C);
  }

  function timelineChart(C) {
    const el = document.getElementById("timeline");
    if (!el) return;
    const tl = data.timeline;
    const short = /\d+s$/.test(tl.freq);
    const label = function (iso) {
      if (short) return iso.slice(11, 19);
      const md = Number(iso.slice(5, 7)) + "/" + Number(iso.slice(8, 10));
      return tl.freq.endsWith("D") ? md : md + " " + iso.slice(11, 16);
    };
    new C(el, {
      type: "bar",
      data: {
        labels: tl.labels.map(label),
        datasets: [
          { label: "수상한 접속", data: tl.suspicious, backgroundColor: COLOR.suspicious, stack: "s",
            borderRadius: 3, borderSkipped: false },
          { label: "그 외 접속", data: tl.total.map(function (t, i) { return t - tl.suspicious[i]; }),
            backgroundColor: COLOR.other, stack: "s", borderRadius: 3, borderSkipped: false },
        ],
      },
      options: {
        datasets: { bar: { categoryPercentage: 0.8, barPercentage: 0.9 } },
        plugins: { tooltip: { mode: "index", intersect: false, callbacks: {
          label: function (c) { return " " + c.dataset.label + " " + c.parsed.y.toLocaleString() + "건"; },
        } } },
        scales: {
          x: { stacked: true, grid: { display: false }, border: { color: COLOR.grid },
               ticks: { maxTicksLimit: narrow ? 4 : 7, maxRotation: 0, autoSkipPadding: 12 } },
          y: { stacked: true, beginAtZero: true, grid: { color: COLOR.grid }, border: { display: false },
               ticks: { precision: 0, maxTicksLimit: 5 } },
        },
      },
    });
  }

  function rulesChart(C) {
    const el = document.getElementById("rules");
    const rows = story.by_rule || [];
    if (!el || !rows.length) return;
    new C(el, {
      type: "bar",
      data: {
        labels: rows.map(function (x) { return x.easy; }),
        datasets: [{ data: rows.map(function (x) { return x.count; }), backgroundColor: COLOR.bar,
          hoverBackgroundColor: COLOR.barHover, borderRadius: 4, borderSkipped: "start",
          barPercentage: 0.7, categoryPercentage: 0.9 }],
      },
      options: {
        indexAxis: "y",
        plugins: { tooltip: { callbacks: { label: function (c) { return " " + c.parsed.x + "곳"; } } } },
        scales: {
          x: { beginAtZero: true, grid: { color: COLOR.grid }, border: { display: false },
               ticks: { precision: 0, maxTicksLimit: 6 } },
          y: { grid: { display: false }, border: { color: COLOR.grid }, ticks: { color: COLOR.label } },
        },
      },
    });
  }

  function ganttChart(C) {
    const box = document.getElementById("gantt-box");
    if (!box || !data.ips.length) return;
    const rows = data.ips.slice(0, Number(box.dataset.rows) || 25);
    box.style.height = Math.max(150, 48 + rows.length * 30) + "px";

    const t0 = Date.parse(data.summary.start);
    const t1 = Date.parse(data.summary.end);
    const span = Math.max(t1 - t0, 1000);
    const minW = Math.max(span * 0.008, 1000);
    const fmt = function (ms) {
      const d = new Date(ms + tzOffsetMs);
      const hm = pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes());
      if (span < 3600e3) return hm + ":" + pad(d.getUTCSeconds());
      if (span < 2 * 86400e3) return hm;
      return (d.getUTCMonth() + 1) + "/" + d.getUTCDate() + " " + hm;
    };

    new C(document.getElementById("gantt"), {
      type: "bar",
      data: {
        labels: rows.map(function (r) { return r.ip; }),
        datasets: [{
          data: rows.map(function (r) {
            const a = Date.parse(r.window.start);
            return [a, Math.max(Date.parse(r.window.end), a + minW)];
          }),
          backgroundColor: rows.map(function (r) { return COLOR.level[r.level]; }),
          borderRadius: 5, borderSkipped: false, barPercentage: 0.62, categoryPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: "y",
        plugins: { tooltip: { callbacks: {
          title: function (items) { return rows[items[0].dataIndex].ip; },
          label: function (c) {
            const r = rows[c.dataIndex];
            return " " + LEVEL_NAME[r.level] + "  " + fmt(Date.parse(r.window.start)) + " ~ " + fmt(Date.parse(r.window.end));
          },
          afterLabel: function (c) {
            return rows[c.dataIndex].findings.map(function (f) { return " · " + (EASY[f.rule] || f.name); }).join("\n");
          },
        } } },
        scales: {
          x: { type: "linear", min: t0, max: t1 + minW, grid: { color: COLOR.grid }, border: { display: false },
               ticks: { maxTicksLimit: narrow ? 3 : 6, callback: function (v) { return fmt(v); } } },
          y: { grid: { display: false }, border: { color: COLOR.grid },
               ticks: { color: COLOR.label, font: { family: "ui-monospace, Menlo, Consolas, monospace", size: 12 } } },
        },
      },
    });
  }

  /* ── 위험도 필터 ─────────────────────────────────────────── */
  const chips = Array.prototype.slice.call(document.querySelectorAll(".chip[data-level]"));
  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      const lv = chip.dataset.level;
      chips.forEach(function (c) { c.setAttribute("aria-pressed", String(c === chip)); });
      document.querySelectorAll(".ip-item").forEach(function (item) {
        item.hidden = !(lv === "all" || item.dataset.level === lv);
      });
    });
  });

  /* ── 할 일 체크 ─────────────────────────────────────────── */
  document.querySelectorAll(".todo input[type=checkbox]").forEach(function (box) {
    box.addEventListener("change", function () { box.closest("li").classList.toggle("is-done", box.checked); });
  });

  /* ── 용어 도우미 열기 ───────────────────────────────────── */
  const glossaryLink = document.getElementById("open-glossary");
  if (glossaryLink) glossaryLink.addEventListener("click", function () {
    const g = document.getElementById("glossary");
    if (g) g.open = true;
  });

  /* ── CSV 저장 (서버에 결과를 남기지 않으므로 브라우저에서 만든다) ── */
  function cell(v) {
    let s = String(v == null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // 엑셀 수식 주입 방지
    return '"' + s.replace(/"/g, '""') + '"';
  }
  const csvBtn = document.getElementById("csv-btn");
  if (csvBtn) csvBtn.addEventListener("click", function () {
    const head = ["IP", "위험도", "나라", "통신사(ASN)", "AbuseIPDB 신뢰도", "찾아낸 행동", "기술적인 설명",
      "요청 수", "1분 최대 요청", "오류 응답 비율(%)", "AI 점수", "의심 구간 시작", "의심 구간 끝", "User-Agent"];
    const rows = [head];
    data.ips.forEach(function (ip) {
      const g = ip.intel.geo || {};
      const ab = ip.intel.abuse || {};
      rows.push([
        ip.ip, LEVEL_NAME[ip.level], g.country_name || "", g.asn ? "AS" + g.asn + " " + g.org : "",
        ab.score == null ? "" : ab.score,
        ip.findings.map(function (f) { return EASY[f.rule] || f.name; }).join(" / "),
        ip.findings.map(function (f) { return f.reason; }).join(" / "),
        ip.stats.requests, ip.stats.peak_60s, ip.stats.err_ratio, ip.ml_score == null ? "" : ip.ml_score,
        ip.window.start, ip.window.end, ip.stats.agent,
      ]);
    });
    const csv = "﻿" + rows.map(function (r) { return r.map(cell).join(","); }).join("\r\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    a.download = "logguard_result.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  /* ── 인쇄: 모든 항목을 펼친 뒤 인쇄하고 원래대로 되돌린다 ── */
  const printBtn = document.getElementById("print-btn");
  if (printBtn) printBtn.addEventListener("click", function () {
    const closed = Array.prototype.filter.call(document.querySelectorAll("details"), function (d) { return !d.open; });
    closed.forEach(function (d) { d.open = true; });
    window.addEventListener("afterprint", function restore() {
      closed.forEach(function (d) { d.open = false; });
      window.removeEventListener("afterprint", restore);
    });
    window.print();
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", setupCharts);
  else setupCharts();
})();
