(function () {
  const el = document.getElementById("report-data");
  if (!el) return;
  const data = JSON.parse(el.textContent);
  const GRID = "#F6E8EE";

  // ── 차트 ──────────────────────────────────────────
  if (window.Chart) {
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.font.size = 12;
    Chart.defaults.color = "#7A6570";
    Chart.defaults.plugins.tooltip.backgroundColor = "#3B2B33";
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 10;
    const tl = data.timeline;
    const fmt = function (iso) {
      if (/\d+s$/.test(tl.freq)) return iso.slice(11, 19);
      const d = iso.slice(5, 16).replace("T", " ");
      return tl.freq.endsWith("D") ? d.slice(0, 5) : d;
    };
    new Chart(document.getElementById("timeline"), {
      type: "bar",
      data: {
        labels: tl.labels.map(fmt),
        datasets: [
          { label: "수상한 접속", data: tl.suspicious, backgroundColor: "#E0475E", stack: "s",
            borderRadius: 4, borderSkipped: false, borderColor: "#FFFFFF", borderWidth: { top: 2 } },
          { label: "그 외 접속", data: tl.total.map(function (t, i) { return t - tl.suspicious[i]; }),
            backgroundColor: "#EAD9E1", stack: "s", borderRadius: 4, borderSkipped: false },
        ],
      },
      options: {
        maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false },
          tooltip: { callbacks: { label: function (c) { return c.dataset.label + " " + c.parsed.y.toLocaleString() + "건"; } } } },
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 8 } },
                  y: { stacked: true, beginAtZero: true, grid: { color: GRID }, border: { display: false } } },
      },
    });

    const byRule = (data.story && data.story.by_rule) || [];
    new Chart(document.getElementById("rules"), {
      type: "bar",
      data: { labels: byRule.map(function (x) { return x.icon + " " + x.easy; }),
        datasets: [{ data: byRule.map(function (x) { return x.count; }), backgroundColor: "#EE8FB4",
          hoverBackgroundColor: "#C93A72", borderRadius: 6, borderSkipped: "start", barPercentage: 0.72 }] },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false },
          tooltip: { callbacks: { label: function (c) { return c.parsed.x + "곳"; } } } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: GRID }, border: { display: false } },
                  y: { grid: { display: false }, ticks: { color: "#5E4A54" } } },
      },
    });
  }

  const EASY = {};
  ((data.story && data.story.by_rule) || []).forEach(function (x) { EASY[x.rule] = x.icon + " " + x.easy; });

  // ── 공격 타임라인 (간트) ───────────────────────────
  const gBox = document.getElementById("gantt-box");
  if (window.Chart && gBox && data.ips.length) {
    gBox.style.height = gBox.dataset.height + "px";
    const rows = data.ips.slice(0, 25);
    const t0 = Date.parse(data.summary.start), t1 = Date.parse(data.summary.end);
    const minW = Math.max((t1 - t0) * 0.006, 1000);
    const color = { "높음": "#E0475E", "중간": "#E8913F", "낮음": "#7C8BDB" };
    const levelName = { "높음": "위험", "중간": "주의", "낮음": "참고" };
    const off = (data.summary.tz_offset_min || 0) * 60e3;
    const pad = function (n) { return String(n).padStart(2, "0"); };
    const fmtT = function (ms) {
      const d = new Date(ms + off);
      const hm = pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes());
      if (t1 - t0 < 3600e3) return hm + ":" + pad(d.getUTCSeconds());
      if (t1 - t0 < 86400e3 * 2) return hm;
      return pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " + hm;
    };
    new Chart(document.getElementById("gantt"), {
      type: "bar",
      data: {
        labels: rows.map(function (r) { return r.ip; }),
        datasets: [{
          data: rows.map(function (r) {
            const a = Date.parse(r.window.start), b = Date.parse(r.window.end);
            return [a, Math.max(b, a + minW)];
          }),
          backgroundColor: rows.map(function (r) { return color[r.level]; }),
          borderRadius: 6, borderSkipped: false, barPercentage: 0.66, categoryPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            label: function (ctx) {
              const r = rows[ctx.dataIndex];
              return levelName[r.level] + "  " + fmtT(Date.parse(r.window.start)) + " ~ " + fmtT(Date.parse(r.window.end));
            },
            afterLabel: function (ctx) {
              return rows[ctx.dataIndex].findings.map(function (f) { return "• " + (EASY[f.rule] || f.name); }).join("\n");
            },
          } },
        },
        scales: {
          x: { type: "linear", min: t0, max: t1 + minW, grid: { color: GRID }, border: { display: false },
               ticks: { maxTicksLimit: 7, callback: function (v) { return fmtT(v); } } },
          y: { grid: { display: false }, ticks: { font: { family: "ui-monospace, Menlo, Consolas, monospace" } } },
        },
      },
    });
  }

  // ── 위험도 필터 ───────────────────────────────────
  document.querySelectorAll(".chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      document.querySelectorAll(".chip").forEach(function (c) { c.classList.remove("active"); });
      chip.classList.add("active");
      const lv = chip.dataset.level;
      document.querySelectorAll(".ip-item").forEach(function (item) {
        item.style.display = lv === "all" || item.dataset.level === lv ? "" : "none";
      });
    });
  });

  // ── CSV 저장 (서버에 저장하지 않으므로 브라우저에서 생성) ──
  function cell(v) {
    let s = String(v == null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;      // 엑셀 수식 주입 방지
    return '"' + s.replace(/"/g, '""') + '"';
  }
  const csvBtn = document.getElementById("csv-btn");
  if (csvBtn) csvBtn.addEventListener("click", function () {
    const rows = [["ip", "위험도", "국가", "통신사(ASN)", "AbuseIPDB 신뢰도", "탐지 유형", "탐지 사유", "요청 수", "60초 최대", "오류 비율(%)", "AI 점수", "의심 구간 시작", "의심 구간 끝", "User-Agent"]];
    data.ips.forEach(function (ip) {
      const g = ip.intel.geo || {}, ab = ip.intel.abuse || {};
      rows.push([ip.ip, ip.level, g.country_name || "", g.asn ? "AS" + g.asn + " " + g.org : "",
        ab.score == null ? "" : ab.score,
        ip.findings.map(function (f) { return f.name; }).join(" / "),
        ip.findings.map(function (f) { return f.reason; }).join(" / "),
        ip.stats.requests, ip.stats.peak_60s, ip.stats.err_ratio, ip.ml_score,
        ip.window.start, ip.window.end, ip.stats.agent]);
    });
    const csv = "﻿" + rows.map(function (r) { return r.map(cell).join(","); }).join("\r\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    a.download = "logguard_result.csv";
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  // ── 할 일 체크 ────────────────────────────────────
  document.querySelectorAll(".todo input").forEach(function (box) {
    box.addEventListener("change", function () { box.closest("li").classList.toggle("done", box.checked); });
  });

  // ── 용어 도우미 열기 ───────────────────────────────
  const gl = document.getElementById("open-glossary");
  if (gl) gl.addEventListener("click", function () { document.getElementById("glossary").open = true; });

  const printBtn = document.getElementById("print-btn");
  if (printBtn) printBtn.addEventListener("click", function () {
    document.querySelectorAll(".ip-item").forEach(function (d) { d.open = true; });
    window.print();
  });
})();
