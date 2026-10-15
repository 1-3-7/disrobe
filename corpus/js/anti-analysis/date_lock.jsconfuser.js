function onLockTriggered() {
  console.log("locked: date lock countermeasure");
  process.exit(0);
}
function table(rows) {
  return rows.map((row) => row.join("|")).join(";");
}
function main() {
  if((new Date()).getTime()<946684800000) { onLockTriggered() }
  if(Date.now()>1262304000000) { onLockTriggered() }
  console.log("unlocked: " + table([["a", 1], ["b", 2]]));
}
main();
