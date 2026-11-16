/* LogGuard 업로드: 파일 선택 표시, 끌어다 놓기, 업로드 전 gzip 압축, 크기 확인 */
(function () {
  "use strict";

  const form = document.getElementById("upload-form");
  if (!form) return;
  const input = document.getElementById("file");
  const zone = document.getElementById("dropzone");
  const title = document.getElementById("dz-title");
  const btn = document.getElementById("submit-btn");
  const errBox = document.getElementById("form-error");
  const defaultTitle = title.textContent;
  const defaultBtn = btn.textContent;
  const maxBytes = Number(form.dataset.maxMb || 50) * 1024 * 1024;
  let ready = false;

  const mb = function (n) { return (n / 1024 / 1024).toFixed(1) + "MB"; };

  function showFile() {
    const f = input.files && input.files[0];
    title.textContent = f ? f.name + " (" + mb(f.size) + ")" : defaultTitle;
    zone.classList.toggle("has-file", Boolean(f));
    errBox.hidden = true;
  }
  function fail(msg) {
    errBox.textContent = msg;
    errBox.hidden = false;
    btn.disabled = false;
    btn.textContent = defaultBtn;
  }

  input.addEventListener("change", showFile);
  ["dragenter", "dragover"].forEach(function (ev) {
    zone.addEventListener(ev, function () { zone.classList.add("is-drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    zone.addEventListener(ev, function () { zone.classList.remove("is-drag"); });
  });
  // 파일 입력칸이 영역 전체를 덮고 있어서, 끌어다 놓으면 브라우저가 알아서 input 에 넣어준다.
  input.addEventListener("drop", function () { setTimeout(showFile, 0); });

  async function isGzip(file) {
    const head = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    return head[0] === 0x1f && head[1] === 0x8b;
  }

  // 로그는 텍스트라 gzip으로 보통 1/10 이하로 줄어든다. 서버는 내용(gzip 시그니처)으로 판별하므로 파일 이름은 그대로 둔다.
  async function compress(file) {
    const stream = file.stream().pipeThrough(new CompressionStream("gzip"));
    const blob = await new Response(stream).blob();
    return new File([blob], file.name, { type: "application/gzip" });
  }

  form.addEventListener("submit", async function (e) {
    if (ready) return;                     // 압축을 마친 뒤의 실제 제출
    e.preventDefault();
    const file = input.files && input.files[0];
    if (!file) return fail("로그 파일을 골라 주세요.");
    btn.disabled = true;
    try {
      let upload = file;
      const canCompress = "CompressionStream" in window && typeof DataTransfer === "function";
      if (canCompress && !(await isGzip(file))) {
        btn.textContent = "파일을 압축하는 중이에요 (" + mb(file.size) + ")";
        upload = await compress(file);
        const dt = new DataTransfer();
        dt.items.add(upload);
        input.files = dt.files;
      }
      if (upload.size > maxBytes) {
        input.value = "";
        showFile();
        return fail("압축해도 " + mb(upload.size) + "라서 올릴 수 있는 크기(" + mb(maxBytes) +
                    ")를 넘어요. 로그를 날짜별로 나누거나 CLI 버전으로 분석해 주세요.");
      }
      btn.textContent = "분석하는 중이에요. 파일 크기에 따라 시간이 걸릴 수 있어요";
      ready = true;
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    } catch (err) {
      fail("파일을 준비하다가 문제가 생겼어요. 다시 시도해 주세요. (" + err.message + ")");
    }
  });

  // 뒤로 가기로 돌아왔을 때 버튼이 '분석 중' 상태로 남지 않게 한다.
  window.addEventListener("pageshow", function () {
    ready = false;
    btn.disabled = false;
    btn.textContent = defaultBtn;
  });
})();
