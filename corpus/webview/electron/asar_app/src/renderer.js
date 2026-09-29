const { formatAmount } = require("./lib/format.js");
const labels = require("./lib/strings.json");

function render(rows) {
  const body = document.querySelector("#rows tbody");
  let total = 0;
  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.textContent = `${row.date} ${row.memo} ${formatAmount(row.cents)}`;
    body.appendChild(tr);
    total += row.cents;
  }
  document.getElementById("total").textContent = formatAmount(total);
  document.title = labels.title;
}

module.exports = { render };
