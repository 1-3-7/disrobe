const API = "https://api.planted.example.com/v2";
async function loadUser(id) {
  const r = await fetch("/api/v3/users/" + id);
  return r.json();
}
function charge() {
  return axios.post("https://pay.planted.example.com/charge");
}
const sock = new WebSocket("wss://live.planted.example.com/stream");
const PROFILE = `query GetPlantedProfile { viewer { id email } }`;
const rel = require("../shared/config.json");
