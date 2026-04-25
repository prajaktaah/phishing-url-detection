console.log("dashboard.js loaded");

/* ================== CHART DEFAULTS ================== */
Chart.defaults.font.family = "'Roboto', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.color = "#555";

/* ================== GLOBAL STATE ================== */
let logs = [];
let darkMode = false;

/* ================== ELEMENTS ================== */
const startDate = document.getElementById("startDate");
const endDate = document.getElementById("endDate");
const categoryFilter = document.getElementById("categoryFilter");

const applyBtn = document.getElementById("applyFilters");
const clearBtn = document.getElementById("clearFilters");
const darkBtn = document.getElementById("toggleDark");

const checkBtn = document.getElementById("checkUrlBtn");
const checkInput = document.getElementById("checkUrlInput");
const checkResult = document.getElementById("checkResult");

const logTable = document.getElementById("logTable");

// KPIs
const totalScanned = document.getElementById("totalScanned");
const totalMalicious = document.getElementById("totalMalicious");
const totalSafe = document.getElementById("totalSafe");
const avgRisk = document.getElementById("avgRisk");

// Charts
let barChart = null;
let pieChart = null;
let lineChart = null;

// Colors
const brownPalette = ["#7A5A3A", "#C1A27A", "#E6D3B1", "#B23A48"];

/* ================== LOAD FROM STORAGE ================== */
chrome.storage.local.get(["logs", "darkMode"], (data) => {
  logs = data.logs || [];
  darkMode = data.darkMode || false;

  if (darkMode) document.body.classList.add("dark-mode");

  renderAll();
  updateChartTitles();
});

/* ================== APPLY FILTERS ================== */
applyBtn.addEventListener("click", () => {
  if (startDate.value && endDate.value && startDate.value > endDate.value) {
    alert("Start date cannot be after End date.");
    return;
  }

  renderAll();
  updateChartTitles();
});

/* ================== CLEAR FILTERS ================== */
clearBtn.addEventListener("click", () => {
  startDate.value = "";
  endDate.value = "";
  categoryFilter.value = "ALL";

  renderAll();
  updateChartTitles();
});

/* ================== DARK MODE ================== */
darkBtn.addEventListener("click", () => {
  darkMode = !darkMode;
  document.body.classList.toggle("dark-mode", darkMode);
  chrome.storage.local.set({ darkMode });
});

/* ================== CHECK URL ================== */
checkBtn.addEventListener("click", async () => {
  const url = checkInput.value.trim();
  if (!url) return;

  try {
    const response = await fetch("http://localhost:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const result = await response.json();
    const parsed = parseBackendResult(result);

    parsed.url = url;
    parsed.time = new Date().toISOString();

    logs.unshift(parsed);
    chrome.storage.local.set({ logs });

    showCheckResult(parsed);
    renderAll();
    updateChartTitles();

  } catch (err) {
    console.error(err);
    alert("Backend not running or unreachable.");
  }
});

/* ================== BACKEND PARSER ================== */
function parseBackendResult(result) {
  if (result.type === "legitimate") {
    return { category: "Safe", risk: null, status: "Safe" };
  }

  if (result.type === "phishing") {
    return {
      category: result.subtype === "malware" ? "Malware" : "Phishing",
      risk: Math.round(result.risk_percent),
      status: "Malicious"
    };
  }

  return { category: "Unknown", risk: null, status: "Unknown" };
}

/* ================== RESULT CARD ================== */
function showCheckResult(entry) {
  checkResult.classList.remove("hidden");

  checkResult.innerHTML =
    entry.risk === null
      ? `<b>${entry.category}</b> — Safe`
      : `<b>${entry.category}</b> — Risk ${entry.risk}%`;

  setTimeout(() => checkResult.classList.add("hidden"), 5000);
}

/* ================== DYNAMIC CHART TITLES ================== */
function updateChartTitles() {
  const start = startDate.value;
  const end = endDate.value;
  const category = categoryFilter.value;

  const dateText =
    start && end ? `${start} → ${end}` :
    start ? `From ${start}` :
    end ? `Until ${end}` :
    "All Time";

  const categoryText =
    category === "ALL" ? "All Categories" : category;

  document.getElementById("barChartTitle").textContent =
    `Categories Detected(${categoryText})`;

  document.getElementById("pieChartTitle").textContent =
    `Threat Breakdown (${categoryText})`;

  document.getElementById("lineChartTitle").textContent =
    `Avg Risk % Over Time(${dateText})`;
}

/* ================== FILTER LOGS ================== */
function getFilteredLogs() {
  return logs.filter(log => {
    const date = new Date(log.time).toISOString().slice(0, 10);

    if (startDate.value && date < startDate.value) return false;
    if (endDate.value && date > endDate.value) return false;

    if (categoryFilter.value !== "ALL" && log.category !== categoryFilter.value) {
      return false;
    }

    return true;
  });
}

/* ================== RENDER ALL ================== */
function renderAll() {
  const filtered = getFilteredLogs();
  renderTable(filtered);
  renderKPIs(filtered);
  renderCharts(filtered);
}

/* ================== TABLE ================== */
function renderTable(data) {
  logTable.innerHTML = "";

  data.forEach(log => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${log.url}</td>
      <td>${log.category}</td>
      <td>${log.status}</td>
      <td>${new Date(log.time).toLocaleString()}</td>
    `;
    logTable.appendChild(row);
  });
}

/* ================== KPIs ================== */
function renderKPIs(data) {
  const total = data.length;
  const malicious = data.filter(d => d.status === "Malicious").length;
  const safe = data.filter(d => d.status === "Safe").length;

  const risks = data.filter(d => d.risk !== null).map(d => d.risk);
  const avg = risks.length
    ? Math.round(risks.reduce((a, b) => a + b, 0) / risks.length)
    : 0;

  totalScanned.textContent = total;
  totalMalicious.textContent = malicious;
  totalSafe.textContent = safe;
  avgRisk.textContent = `${avg}%`;
}

/* ================== CHARTS ================== */
function destroyCharts() {
  if (barChart) barChart.destroy();
  if (pieChart) pieChart.destroy();
  if (lineChart) lineChart.destroy();
}

function renderCharts(data) {
  destroyCharts();

  const counts = { Safe: 0, Phishing: 0, Malware: 0, IDN: 0 };

  data.forEach(d => {
    if (counts[d.category] !== undefined) {
      counts[d.category]++;
    }
  });

  barChart = new Chart(document.getElementById("barChart"), {
    type: "bar",
    data: {
      labels: Object.keys(counts),
      datasets: [{
        data: Object.values(counts),
        backgroundColor: brownPalette
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } }
    }
  });

  pieChart = new Chart(document.getElementById("pieChart"), {
    type: "pie",
    data: {
      labels: Object.keys(counts),
      datasets: [{
        data: Object.values(counts),
        backgroundColor: brownPalette
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      radius: "70%"
    }
  });

  const lineData = data
    .filter(d => d.risk !== null)
    .reverse();

    lineChart = new Chart(document.getElementById("lineChart"), {
      type: "line",
      data: {
        labels: lineData.map(d => new Date(d.time).toLocaleTimeString()),
        datasets: [{
          label: "Average Risk (%)",   // ✅ ADD THIS LINE
          data: lineData.map(d => d.risk),
          fill: true,
          borderColor: "#7A5A3A",
          backgroundColor: "rgba(122,90,58,0.2)",
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, max: 100 }
        }
      }
    });
}