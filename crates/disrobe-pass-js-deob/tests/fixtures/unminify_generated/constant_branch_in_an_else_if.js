var a = 1;
if (a) { console.log('a'); } else if (!0) { let b = 1; console.log('b', b); } else { if (a) { console.log('c'); } }
if (a) { console.log('d'); } else if (!1) { console.log('e'); }
console.log('f');
