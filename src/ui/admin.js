"use strict";

// Admin console client. Talks to the same-origin /api/* JSON endpoints.
// Security: never assign untrusted strings (titles, slugs, emails) via innerHTML.
// All preview-derived text is set with textContent / created as DOM nodes.
(function () {
  let csrf = "";
  let previewBaseUrl = "";

  const els = {
    accountEmail: document.querySelector("[data-account-email]"),
    signout: document.querySelector("[data-signout]"),
    uploadForm: document.querySelector("[data-upload-form]"),
    uploadSubmit: document.querySelector("[data-upload-submit]"),
    uploadError: document.querySelector("[data-upload-error]"),
    uploadResult: document.querySelector("[data-upload-result]"),
    resultText: document.querySelector("[data-result-text]"),
    resultCopy: document.querySelector("[data-result-copy]"),
    dropzone: document.querySelector("[data-dropzone]"),
    fileTrigger: document.querySelector("[data-file-trigger]"),
    fileInput: document.querySelector("[data-file-input]"),
    fileName: document.querySelector("[data-file-name]"),
    htmlInput: document.querySelector("[data-html-input]"),
    rows: document.querySelector("[data-rows]"),
    empty: document.querySelector("[data-empty]"),
    listError: document.querySelector("[data-list-error]"),
  };

  function showError(node, message) {
    if (!node) return;
    node.textContent = message;
    node.hidden = false;
  }

  function clearError(node) {
    if (!node) return;
    node.textContent = "";
    node.hidden = true;
  }

  async function readJson(response) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  function apiErrorMessage(body, fallback) {
    if (body && body.error && typeof body.error.message === "string") {
      return body.error.message;
    }
    return fallback;
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  function flashButton(button, message) {
    if (!button) return;
    const original = button.textContent;
    button.textContent = message;
    setTimeout(function () {
      button.textContent = original;
    }, 1400);
  }

  function shareText(url, password) {
    return "link: " + url + "\npassword: " + password;
  }

  function previewUrl(slug) {
    return previewBaseUrl.replace(/\/$/, "") + "/p/" + slug;
  }

  function formatDate(value) {
    if (!value) return "Never";
    const ts = Date.parse(value);
    if (!Number.isFinite(ts)) return value;
    return new Date(ts).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }

  function statusOf(preview) {
    if (preview.deletedAt) return "unpublished";
    if (preview.expiresAt && Date.parse(preview.expiresAt) <= Date.now()) return "expired";
    return "active";
  }

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text == null ? "" : String(text);
    return td;
  }

  function renderRow(preview) {
    const tr = document.createElement("tr");
    const url = previewUrl(preview.slug);

    const titleTd = document.createElement("td");
    const link = document.createElement("a");
    link.href = url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = preview.title;
    titleTd.appendChild(link);
    tr.appendChild(titleTd);

    const slugTd = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = preview.slug;
    slugTd.appendChild(code);
    tr.appendChild(slugTd);

    tr.appendChild(cell(preview.publisherEmail));
    tr.appendChild(cell(formatDate(preview.createdAt)));
    tr.appendChild(cell(formatDate(preview.expiresAt)));

    const status = statusOf(preview);
    const statusTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "status status-" + status;
    badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    statusTd.appendChild(badge);
    tr.appendChild(statusTd);

    // Password column: set/reset a viewer password.
    const pwTd = document.createElement("td");
    pwTd.className = "password-cell";
    const pwForm = document.createElement("form");
    const pwInput = document.createElement("input");
    pwInput.type = "password";
    pwInput.placeholder = "New password";
    pwInput.minLength = 5;
    pwInput.maxLength = 256;
    pwInput.autocomplete = "new-password";
    const pwSave = document.createElement("button");
    pwSave.type = "submit";
    pwSave.className = "btn";
    pwSave.textContent = "Save";
    pwForm.appendChild(pwInput);
    pwForm.appendChild(pwSave);
    pwForm.addEventListener("submit", function (event) {
      event.preventDefault();
      resetPassword(preview, pwInput, pwSave);
    });
    pwTd.appendChild(pwForm);
    tr.appendChild(pwTd);

    // Actions column.
    const actionsTd = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "actions-cell";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn";
    copyBtn.textContent = "Copy link";
    copyBtn.addEventListener("click", async function () {
      const ok = await copyText(url);
      flashButton(copyBtn, ok ? "Copied!" : "Copy failed");
    });
    actions.appendChild(copyBtn);

    if (status !== "unpublished") {
      const unpublishBtn = document.createElement("button");
      unpublishBtn.type = "button";
      unpublishBtn.className = "btn";
      unpublishBtn.textContent = "Unpublish";
      unpublishBtn.addEventListener("click", function () {
        unpublish(preview, unpublishBtn);
      });
      actions.appendChild(unpublishBtn);
    }

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "btn btn-danger";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", function () {
      hardDelete(preview, deleteBtn);
    });
    actions.appendChild(deleteBtn);

    const htmlLink = document.createElement("a");
    htmlLink.className = "btn";
    htmlLink.href = "/api/previews/" + encodeURIComponent(preview.slug) + "/html";
    htmlLink.textContent = "HTML";
    actions.appendChild(htmlLink);

    actionsTd.appendChild(actions);
    tr.appendChild(actionsTd);

    return tr;
  }

  function renderRows(previews) {
    els.rows.replaceChildren();
    if (!previews.length) {
      els.empty.hidden = false;
      return;
    }
    els.empty.hidden = true;
    const fragment = document.createDocumentFragment();
    previews.forEach(function (preview) {
      fragment.appendChild(renderRow(preview));
    });
    els.rows.appendChild(fragment);
  }

  async function loadPreviews() {
    clearError(els.listError);
    const response = await fetch("/api/previews", { headers: { Accept: "application/json" } });
    if (response.status === 401) {
      window.location.assign("/login");
      return;
    }
    const body = await readJson(response);
    if (!response.ok || !body) {
      showError(els.listError, apiErrorMessage(body, "Failed to load pages."));
      return;
    }
    renderRows(Array.isArray(body.previews) ? body.previews : []);
  }

  async function postJson(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  async function resetPassword(preview, input, button) {
    const password = input.value;
    if (password.length < 5) {
      input.focus();
      return;
    }
    button.disabled = true;
    try {
      const response = await postJson(
        "/api/previews/" + encodeURIComponent(preview.slug) + "/password",
        { csrf: csrf, password: password },
      );
      const body = await readJson(response);
      if (!response.ok) {
        flashButton(button, "Failed");
        showError(els.listError, apiErrorMessage(body, "Could not reset password."));
        return;
      }
      input.value = "";
      const ok = await copyText(shareText(previewUrl(preview.slug), password));
      flashButton(button, ok ? "Copied!" : "Saved");
    } finally {
      button.disabled = false;
    }
  }

  async function unpublish(preview, button) {
    if (!window.confirm('Unpublish "' + preview.title + '"? Viewers will no longer be able to open it.')) {
      return;
    }
    button.disabled = true;
    const response = await postJson(
      "/api/previews/" + encodeURIComponent(preview.slug) + "/unpublish",
      { csrf: csrf },
    );
    if (!response.ok) {
      const body = await readJson(response);
      showError(els.listError, apiErrorMessage(body, "Could not unpublish."));
      button.disabled = false;
      return;
    }
    await loadPreviews();
  }

  async function hardDelete(preview, button) {
    if (!window.confirm('Permanently delete "' + preview.title + '"? This cannot be undone.')) {
      return;
    }
    button.disabled = true;
    const response = await postJson(
      "/api/previews/" + encodeURIComponent(preview.slug) + "/delete",
      { csrf: csrf, confirmSlug: preview.slug },
    );
    if (!response.ok) {
      const body = await readJson(response);
      showError(els.listError, apiErrorMessage(body, "Could not delete."));
      button.disabled = false;
      return;
    }
    await loadPreviews();
  }

  function setSelectedFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function () {
      els.htmlInput.value = typeof reader.result === "string" ? reader.result : "";
      els.fileName.textContent = "Loaded " + file.name;
      els.fileName.hidden = false;
    };
    reader.readAsText(file);
  }

  async function submitUpload(event) {
    event.preventDefault();
    clearError(els.uploadError);
    els.uploadResult.hidden = true;

    const form = els.uploadForm;
    const title = form.elements.title.value.trim();
    const password = form.elements.password.value;
    const html = els.htmlInput.value;

    if (!title || !password || !html.trim()) {
      showError(els.uploadError, "Title, password, and HTML are all required.");
      return;
    }

    els.uploadSubmit.disabled = true;
    try {
      const response = await postJson("/api/previews", {
        csrf: csrf,
        title: title,
        password: password,
        html: html,
      });
      const body = await readJson(response);
      if (!response.ok || !body) {
        showError(els.uploadError, apiErrorMessage(body, "Upload failed."));
        return;
      }

      els.resultText.textContent = shareText(body.url, password);
      els.uploadResult.hidden = false;
      form.reset();
      els.htmlInput.value = "";
      els.fileName.hidden = true;
      els.fileName.textContent = "";
      await loadPreviews();
    } finally {
      els.uploadSubmit.disabled = false;
    }
  }

  function wireUpload() {
    els.uploadForm.addEventListener("submit", submitUpload);
    els.fileTrigger.addEventListener("click", function () {
      els.fileInput.click();
    });
    els.fileInput.addEventListener("change", function () {
      setSelectedFile(els.fileInput.files && els.fileInput.files[0]);
    });

    ["dragenter", "dragover"].forEach(function (type) {
      els.dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        els.dropzone.classList.add("is-dragover");
      });
    });
    ["dragleave", "dragend", "drop"].forEach(function (type) {
      els.dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        els.dropzone.classList.remove("is-dragover");
      });
    });
    els.dropzone.addEventListener("drop", function (event) {
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      setSelectedFile(file);
    });

    els.resultCopy.addEventListener("click", async function () {
      const ok = await copyText(els.resultText.textContent || "");
      flashButton(els.resultCopy, ok ? "Copied!" : "Copy failed");
    });
  }

  function wireAccount() {
    els.signout.addEventListener("click", async function () {
      const response = await postJson("/logout", { csrf: csrf });
      window.location.assign(response.url && response.redirected ? response.url : "/login");
    });
  }

  async function init() {
    const response = await fetch("/api/session", { headers: { Accept: "application/json" } });
    if (response.status === 401) {
      window.location.assign("/login");
      return;
    }
    const body = await readJson(response);
    if (!response.ok || !body) {
      showError(els.listError, "Could not start admin session.");
      return;
    }
    csrf = body.csrf || "";
    previewBaseUrl = body.previewBaseUrl || window.location.origin;
    if (body.user && body.user.email) {
      els.accountEmail.textContent = body.user.email;
    }
    wireAccount();
    wireUpload();
    await loadPreviews();
  }

  init();
})();
