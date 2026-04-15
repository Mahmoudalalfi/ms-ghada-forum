var tableBody = document.getElementById("tableBody");
var statusText = document.getElementById("statusText");
var emptyState = document.getElementById("emptyState");
var searchInput = document.getElementById("searchInput");
var courseFilter = document.getElementById("courseFilter");
var courseFilterSelect = document.getElementById("courseFilterSelect");
var courseFilterTrigger = document.getElementById("courseFilterTrigger");
var courseFilterLabel = document.getElementById("courseFilterLabel");
var courseFilterPanel = document.getElementById("courseFilterPanel");
var courseFilterOptions = courseFilterPanel.querySelectorAll(".filter-option");
var logoutBtn = document.getElementById("logoutBtn");
var changePasswordBtn = document.getElementById("changePasswordBtn");
var cpModal = document.getElementById("cpModal");
var cpModalClose = document.getElementById("cpModalClose");
var cpCancelBtn = document.getElementById("cpCancelBtn");
var cpSubmitBtn = document.getElementById("cpSubmitBtn");
var cpCurrent = document.getElementById("cpCurrent");
var cpNew = document.getElementById("cpNew");
var cpConfirm = document.getElementById("cpConfirm");
var cpError = document.getElementById("cpError");
var cpSuccess = document.getElementById("cpSuccess");
var linksBtn = document.getElementById("linksBtn");
var refreshBtn = document.getElementById("refreshBtn");
var exportBtn = document.getElementById("exportBtn");
var pagination = document.getElementById("pagination");
var prevBtn = document.getElementById("prevBtn");
var nextBtn = document.getElementById("nextBtn");
var pageInfo = document.getElementById("pageInfo");
var pageSizeSelectWrap = document.getElementById("pageSizeSelectWrap");
var pageSizeTrigger = document.getElementById("pageSizeTrigger");
var pageSizeLabel = document.getElementById("pageSizeLabel");
var pageSizePanel = document.getElementById("pageSizePanel");
var pageSizeOptions = pageSizePanel.querySelectorAll(".filter-option");
var currentPageSize = 50;

var rowsCache = [];
var searchTimer = null;
var currentPage = 1;
var totalPages = 1;
var totalCount = 0;

function toCsv(rows) {
  var headers = ["id","student_name","student_school","student_phone","parent_phone","course","discover_source","created_at"];
  var lines = [headers.join(",")];
  rows.forEach(function(row) {
    lines.push(headers.map(function(h) {
      return '"' + (row[h] == null ? "" : String(row[h])).replace(/"/g, '""') + '"';
    }).join(","));
  });
  return lines.join("\n");
}

function createCell(text) {
  var td = document.createElement("td");
  td.textContent = text == null ? "" : String(text);
  return td;
}

function createCoursePill(text) {
  var td = document.createElement("td");
  var span = document.createElement("span");
  span.className = "course-pill";
  span.textContent = text == null ? "" : String(text);
  td.appendChild(span);
  return td;
}

function createDeleteBtn(id) {
  var td = document.createElement("td");
  var btn = document.createElement("button");
  btn.className = "delete-btn";
  btn.dataset.id = id;
  btn.textContent = "Delete";
  td.appendChild(btn);
  return td;
}

function renderTable(rows) {
  while (tableBody.firstChild) tableBody.removeChild(tableBody.firstChild);
  if (!rows.length) { emptyState.hidden = false; return; }
  emptyState.hidden = true;
  rows.forEach(function(row) {
    var tr = document.createElement("tr");
    tr.appendChild(createCell(row.id));
    tr.appendChild(createCell(row.student_name));
    tr.appendChild(createCell(row.student_school));
    tr.appendChild(createCell(row.student_phone));
    tr.appendChild(createCell(row.parent_phone));
    tr.appendChild(createCoursePill(row.course));
    tr.appendChild(createCell(row.discover_source));
    tr.appendChild(createCell(row.created_at));
    tr.appendChild(createDeleteBtn(row.id));
    tableBody.appendChild(tr);
  });
}

function updatePaginationControls() {
  if (totalPages <= 1 && totalCount === 0) {
    pagination.hidden = true;
    return;
  }
  pagination.hidden = false;
  var start = totalCount === 0 ? 0 : (currentPage - 1) * currentPageSize + 1;
  var end = Math.min(currentPage * currentPageSize, totalCount);
  pageInfo.textContent = start + "–" + end + " of " + totalCount;
  prevBtn.disabled = currentPage <= 1;
  nextBtn.disabled = currentPage >= totalPages;
}

function closeCourseFilter() {
  courseFilterSelect.classList.remove("open");
  courseFilterTrigger.setAttribute("aria-expanded", "false");
}

function setCourseFilter(value) {
  courseFilter.value = value;
  courseFilterLabel.textContent = value || "All Courses";
  courseFilterOptions.forEach(function(o) { o.classList.toggle("active", o.dataset.value === value); });
}

async function loadRegistrations(page) {
  if (page !== undefined) currentPage = page;
  statusText.textContent = "Loading\u2026";
  var params = new URLSearchParams();
  var search = searchInput.value.trim();
  var course = courseFilter.value.trim();
  if (search) params.set("search", search);
  if (course) params.set("course", course);
  params.set("page", String(currentPage));
  params.set("limit", String(currentPageSize));
  var response = await fetch("/api/registrations?" + params.toString());
  if (!response.ok) throw new Error("Failed to load registrations.");
  var data = await response.json();
  totalCount = data.total || 0;
  totalPages = data.totalPages || 1;
  currentPage = data.page || 1;
  rowsCache = Array.isArray(data.rows) ? data.rows : [];
  renderTable(rowsCache);
  updatePaginationControls();
  statusText.textContent = "Showing " + totalCount + " registration(s) total.";
}

async function exportAll() {
  statusText.textContent = "Exporting\u2026";
  var params = new URLSearchParams();
  var search = searchInput.value.trim();
  var course = courseFilter.value.trim();
  if (search) params.set("search", search);
  if (course) params.set("course", course);
  params.set("page", "1");
  params.set("limit", "200");

  var allRows = [];
  var pg = 1;
  var pages = 1;
  do {
    params.set("page", String(pg));
    var response = await fetch("/api/registrations?" + params.toString());
    if (!response.ok) throw new Error("Failed to export.");
    var data = await response.json();
    pages = data.totalPages || 1;
    allRows = allRows.concat(Array.isArray(data.rows) ? data.rows : []);
    pg++;
  } while (pg <= pages);

  var blob = new Blob([toCsv(allRows)], { type: "text/csv;charset=utf-8;" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a"); a.href = url; a.download = "registrations.csv"; a.click();
  URL.revokeObjectURL(url);
  statusText.textContent = "Exported " + allRows.length + " registration(s).";
}

async function deleteRegistration(id) {
  if (!window.confirm("Delete registration #" + id + "?")) return;
  var response = await fetch("/api/registrations/" + id, { method: "DELETE", headers: { "X-Requested-With": "XMLHttpRequest" } });
  if (!response.ok) {
    var p = await response.json().catch(function() { return {}; });
    throw new Error(p.error || "Failed to delete.");
  }
}

tableBody.addEventListener("click", async function(e) {
  var btn = e.target.closest(".delete-btn");
  if (!btn) return;
  var id = Number.parseInt(btn.dataset.id, 10);
  if (!id) return;
  try { await deleteRegistration(id); await loadRegistrations(); }
  catch(err) { statusText.textContent = err.message; }
});

searchInput.addEventListener("input", function() {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(function() {
    loadRegistrations(1).catch(function(e) { statusText.textContent = e.message; });
  }, 300);
});

courseFilterTrigger.addEventListener("click", function() {
  var isOpen = courseFilterSelect.classList.toggle("open");
  courseFilterTrigger.setAttribute("aria-expanded", String(isOpen));
});

courseFilterOptions.forEach(function(o) {
  o.addEventListener("click", function() {
    setCourseFilter(o.dataset.value);
    closeCourseFilter();
    loadRegistrations(1).catch(function(e) { statusText.textContent = e.message; });
  });
});

document.addEventListener("click", function(e) { if (!courseFilterSelect.contains(e.target)) closeCourseFilter(); });
document.addEventListener("keydown", function(e) { if (e.key === "Escape") { closeCourseFilter(); closePageSizeFilter(); } });
refreshBtn.addEventListener("click", function() { loadRegistrations().catch(function(e) { statusText.textContent = e.message; }); });

prevBtn.addEventListener("click", function() {
  if (currentPage > 1) loadRegistrations(currentPage - 1).catch(function(e) { statusText.textContent = e.message; });
});
nextBtn.addEventListener("click", function() {
  if (currentPage < totalPages) loadRegistrations(currentPage + 1).catch(function(e) { statusText.textContent = e.message; });
});
function closePageSizeFilter() {
  pageSizeSelectWrap.classList.remove("open");
  pageSizeTrigger.setAttribute("aria-expanded", "false");
}

pageSizeTrigger.addEventListener("click", function() {
  var isOpen = pageSizeSelectWrap.classList.toggle("open");
  pageSizeTrigger.setAttribute("aria-expanded", String(isOpen));
});

pageSizeOptions.forEach(function(o) {
  o.addEventListener("click", function() {
    currentPageSize = Number(o.dataset.value);
    pageSizeLabel.textContent = o.textContent;
    pageSizeOptions.forEach(function(opt) { opt.classList.toggle("active", opt === o); });
    closePageSizeFilter();
    loadRegistrations(1).catch(function(e) { statusText.textContent = e.message; });
  });
});

document.addEventListener("click", function(e) {
  if (!pageSizeSelectWrap.contains(e.target)) closePageSizeFilter();
});

exportBtn.addEventListener("click", function() {
  exportAll().catch(function(e) { statusText.textContent = e.message; });
});

linksBtn.addEventListener("click", async function() {
  try {
    var response = await fetch("/api/admin/course-links");
    if (!response.ok) throw new Error("Could not generate course links.");
    var payload = await response.json();
    var lines = ["Course Links (expires in " + payload.expiresInDays + " days):", ""];
    payload.links.forEach(function(entry) { lines.push(entry.course + ": " + entry.link); });
    var blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a"); a.href = url; a.download = "course-links.txt"; a.click();
    URL.revokeObjectURL(url);
    statusText.textContent = "Course links file downloaded.";
  } catch(err) { statusText.textContent = err.message; }
});

function openCpModal() {
  cpCurrent.value = ""; cpNew.value = ""; cpConfirm.value = "";
  cpError.hidden = true; cpSuccess.hidden = true;
  cpModal.hidden = false;
  cpCurrent.focus();
}
function closeCpModal() { cpModal.hidden = true; }

changePasswordBtn.addEventListener("click", openCpModal);
cpModalClose.addEventListener("click", closeCpModal);
cpCancelBtn.addEventListener("click", closeCpModal);
cpModal.addEventListener("click", function(e) { if (e.target === cpModal) closeCpModal(); });
document.addEventListener("keydown", function(e) { if (e.key === "Escape" && !cpModal.hidden) closeCpModal(); });

cpSubmitBtn.addEventListener("click", async function() {
  cpError.hidden = true; cpSuccess.hidden = true;
  var current = cpCurrent.value;
  var newPw = cpNew.value;
  var confirm = cpConfirm.value;
  if (!current || !newPw || !confirm) {
    cpError.textContent = "All fields are required.";
    cpError.hidden = false; return;
  }
  cpSubmitBtn.disabled = true; cpSubmitBtn.textContent = "Updating…";
  try {
    var response = await fetch("/api/admin/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
      body: JSON.stringify({ currentPassword: current, newPassword: newPw, confirmPassword: confirm })
    });
    var data = await response.json();
    if (!response.ok) {
      cpError.textContent = data.error || "Failed to update password.";
      cpError.hidden = false;
    } else {
      cpSuccess.textContent = "Password updated successfully!";
      cpSuccess.hidden = false;
      cpCurrent.value = ""; cpNew.value = ""; cpConfirm.value = "";
      setTimeout(closeCpModal, 1800);
    }
  } catch(err) {
    cpError.textContent = "Network error. Please try again.";
    cpError.hidden = false;
  } finally {
    cpSubmitBtn.disabled = false; cpSubmitBtn.textContent = "Update Password";
  }
});

logoutBtn.addEventListener("click", async function() {
  try {
    await fetch("/api/admin/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: "{}"
    });
  } catch(_) {}
  window.location.href = "/";
});

document.addEventListener("contextmenu", function(e) { e.preventDefault(); });
document.addEventListener("copy", function(e) { e.preventDefault(); });
document.addEventListener("cut", function(e) { e.preventDefault(); });
document.addEventListener("dragstart", function(e) { e.preventDefault(); });
document.addEventListener("selectstart", function(e) { e.preventDefault(); });

setCourseFilter(courseFilter.value);
loadRegistrations(1).catch(function(e) { statusText.textContent = e.message; });
