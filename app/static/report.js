(function () {
  const el = document.getElementById("report-data");
  if (!el) return;
  const data = JSON.parse(el.textContent);

  // ── 차트 ──────────────────────────────────────────
  if (window.Chart) {
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.color = "#7a8190";
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
          { label: "탐지된 IP 요청", data: tl.suspicious, backgroundColor: "#d84a4a", stack: "s" },
          { label: "그 외 요청", data: tl.total.map(function (t, i) { return t - tl.suspicious[i]; }),
            backgroundColor: "#c9ced8", stack: "s" },
        ],
      },
      options: {
        maintainAspectRatio: false, animation: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 8 } },
                  y: { stacked: true, beginAtZero: true, grid: { color: "#eef1f5" } } },
      },
    });

    const rc = data.rule_counts;
    const names = Object.keys(rc).sort(function (a, b) { return rc[b] - rc[a]; });
    new Chart(document.getElementById("rules"), {
      type: "bar",
      data: { labels: names, datasets: [{ data: names.map(function (n) { return rc[n]; }),
        backgroundColor: names.map(function (n) { return n.startsWith("AI") ? "#7e57c2" : "#2f5d8f"; }),
        borderRadius: 4 }] },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#eef1f5" } },
                  y: { grid: { display: false } } },
      },
    });
  }

  // ── 공격 타임라인 (간트) ───────────────────────────
  const gBox = document.getElementById("gantt-box");
  if (window.Chart && gBox && data.ips.length) {
    gBox.style.height = gBox.dataset.height + "px";
    const rows = data.ips.slice(0, 25);
    const t0 = Date.parse(data.summary.start), t1 = Date.parse(data.summary.end);
    const minW = Math.max((t1 - t0) * 0.006, 1000);
    const color = { "높음": "#c62828", "중간": "#e08a00", "낮음": "#2f5d8f" };
    const pad = function (n) { return String(n).padStart(2, "0"); };
    const fmtT = function (ms) {
      const d = new Date(ms);
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
          borderRadius: 3, barPercentage: 0.7, categoryPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            label: function (ctx) {
              const r = rows[ctx.dataIndex];
              return r.level + " · " + fmtT(Date.parse(r.window.start)) + " ~ " + fmtT(Date.parse(r.window.end));
            },
            afterLabel: function (ctx) {
              return rows[ctx.dataIndex].findings.map(function (f) { return "• " + f.name; }).join("\n");
            },
          } },
        },
        scales: {
          x: { type: "linear", min: t0, max: t1 + minW, grid: { color: "#eef1f5" },
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

  const printBtn = document.getElementById("print-btn");
  if (printBtn) printBtn.addEventListener("click", function () {
    document.querySelectorAll(".ip-item").forEach(function (d) { d.open = true; });
    window.print();
  });
})();
