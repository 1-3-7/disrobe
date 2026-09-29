const { app, BrowserWindow } = require("electron");
const path = require("node:path");

function createWindow() {
  const win = new BrowserWindow({
    width: 960,
    height: 640,
    webPreferences: { preload: path.join(__dirname, "src", "renderer.js") },
  });
  win.loadFile(path.join(__dirname, "index.html"));
}

app.whenReady().then(createWindow);
app.on("window-all-closed", () => app.quit());
