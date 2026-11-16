(function () {
  const form = document.getElementById("upload-form");
  if (!form) return;
  const input = document.getElementById("file");
  const zone = document.getElementById("dropzone");
  const title = document.getElementById("dz-title");
  const btn = document.getElementById("submit-btn");
  const errBox = document.getElementById("form-error");
  const maxBytes = Number(form.dataset.maxMb || 50) * 1024 * 1024;
  let ready = false;

  const mb = function (n) { return (n / 1024 / 1024).toFixed(1) + "MB"; };
  function showName() {
    if (input.files && input.files[0]) {
      const f = input.files[0];
      title.textContent = f.name + " (" + mb(f.size) + ")";
      zone.classList.add("has-file");
      errBox.hidden = true;
    }
  }
  function fail(msg) {
    errBox.textContent = msg;
    errBox.hidden = false;
    btn.disabled = false;
    btn.textContent = "분석 시작";
  }

  input.addEventListener("change", showName);
  ["dragenter", "dragover"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove("drag"); });
  });
  zone.addEventListener("drop", function (e) {
    if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; showName(); }
  });

  async function isGzip(file) {
    const head = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    return head[0] === 0x1f && head[1] === 0x8b;
  }

  // 로그는 텍스트라 gzip으로 보통 1/10 이하로 줄어든다. 업로드 전에 브라우저에서 압축해 전송량과 업로드 제한을 줄인다.
  async function compress(file) {
    const stream = file.stream().pipeThrough(new CompressionStream("gzip"));
    const blob = await new Response(stream).blob();
    return new File([blob], file.name, { type: "application/gzip" });   // 서버는 내용(gzip 시그니처)으로 판별하므로 이름은 그대로
  }

  form.addEventListener("submit", async function (e) {
    if (ready) return;                         // 압축이 끝난 뒤의 실제 제출
    e.preventDefault();
    const file = input.files && input.files[0];
    if (!file) return fail("로그 파일을 선택해 주세요.");
    btn.disabled = true;
    try {
      let upload = file;
      if (!(await isGzip(file)) && "CompressionStream" in window && typeof DataTransfer === "function") {
        btn.textContent = "압축 중… (" + mb(file.size) + ")";
        upload = await compress(file);
        const dt = new DataTransfer();
        dt.items.add(upload);
        input.files = dt.files;
      }
      if (upload.size > maxBytes) {
        input.value = "";
        title.textContent = "로그 파일을 끌어다 놓거나 클릭해서 선택";
        zone.classList.remove("has-file");
        return fail("압축 후에도 " + mb(upload.size) + "라서 제한(" + mb(maxBytes) +
                    ")을 넘습니다. 로그를 날짜별로 나누거나 CLI 버전으로 분석해 주세요.");
      }
      btn.textContent = "분석 중입니다… 로그 크기에 따라 시간이 걸릴 수 있어요";
      ready = true;
      form.requestSubmit ? form.requestSubmit() : form.submit();
    } catch (err) {
      fail("파일을 준비하는 중 문제가 생겼습니다: " + err.message);
    }
  });
})();
