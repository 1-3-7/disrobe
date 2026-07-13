const userInput = location.hash.slice(1);
const el = document.getElementById("out");

el.innerHTML = userInput; // Noncompliant {{S5696}}
el.outerHTML = userInput; // Noncompliant {{S5696}}
el["innerHTML"] = userInput; // Noncompliant {{S5696}}
document.write(userInput); // Noncompliant {{S5696}}
document.writeln(userInput); // Noncompliant {{S5696}}
el.insertAdjacentHTML("beforeend", userInput); // Noncompliant {{S5696}}
location.href = userInput; // Noncompliant {{S5696}}
window.location = userInput; // Noncompliant {{S5696}}
window.location.href = userInput; // Noncompliant {{S5696}}
location = userInput; // Noncompliant {{S5696}}

el.innerHTML = "<b>static and safe</b>";
el.outerHTML = "<span>fixed</span>";
document.write("<p>constant markup</p>");
el.insertAdjacentHTML("beforeend", "<i>ok</i>");
location.href = "https://example.com/landing";
const current = location.href;
el.textContent = userInput;
