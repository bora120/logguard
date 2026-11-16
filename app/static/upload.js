(function () {
  const form = document.getElementById("upload-form");
  const input = document.getElementById("file");
  const zone = document.getElementById("dropzone");
  const title = document.getElementById("dz-title");
  const btn = document.getElementById("submit-btn");
  if (!form) return;

  function showName() {
    if (input.files && input.files[0]) {
      const f = input.files[0];
      title.textContent = f.name + " (" + (f.size / 1024 / 1024).toFixed(1) + "MB)";
      zone.classList.add("has-file");
    }
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
  form.addEventListener("submit", function () {
    btn.disabled = true;
    btn.textContent = "분석 중입니다… 로그 크기에 따라 시간이 걸릴 수 있어요";
  });
})();
