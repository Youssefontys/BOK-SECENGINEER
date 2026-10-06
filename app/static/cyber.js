// Decoratieve interactie. Bewust een apart bestand en geen inline script,
// zodat de Content-Security-Policy op script-src 'self' kan blijven staan
// zonder 'unsafe-inline': geinjecteerde markup kan dan nog steeds niets
// uitvoeren, alleen dit bestand mag dat.
(function () {
  "use strict";

  var root = document.documentElement;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Alleen de inlog- en registratiepagina's nemen de scene op. Op de
  // ingelogde pagina's is er niets om te besturen, dus doet dit script
  // daar ook niets.
  if (!document.querySelector(".scene")) {
    return;
  }

  // Muispositie als 0..1 waarden in CSS-variabelen. De verplaatsing zelf
  // doet CSS; JS geeft alleen de coordinaten door.
  if (!reduced) {
    window.addEventListener(
      "pointermove",
      function (event) {
        root.style.setProperty("--mx", (event.clientX / window.innerWidth).toFixed(3));
        root.style.setProperty("--my", (event.clientY / window.innerHeight).toFixed(3));
      },
      { passive: true }
    );
  }

  var lines = [
    "poging geregistreerd ~ bron: lokale sessie",
    "niets te zien hier, probeer het inlogveld",
    "klik gelogd ~ 1 gebeurtenis in de wachtrij",
    "scan afgeslagen ~ geen open poort gevonden",
    "nette poging. volgende keer met een geldige code"
  ];
  var index = 0;
  var ticker = document.querySelector("[data-ticker]");
  var timer = null;

  // Reageren op een klik buiten de invoervelden: de figuur kijkt op en de
  // regel onderin verandert.
  document.addEventListener("click", function (event) {
    if (event.target.closest("input, textarea, button, a, label, select")) {
      return;
    }

    document.body.classList.add("alerted");
    window.clearTimeout(timer);
    timer = window.setTimeout(function () {
      document.body.classList.remove("alerted");
    }, 1400);

    if (ticker) {
      ticker.textContent = lines[index % lines.length];
      index += 1;
    }

    if (reduced) {
      return;
    }

    // Korte puls op de plek van de klik. De positie gaat via CSSOM en niet
    // via een style-attribuut in de HTML, dus de strikte style-src blijft
    // gelden.
    var ripple = document.createElement("span");
    ripple.className = "ripple";
    ripple.style.setProperty("--x", event.clientX + "px");
    ripple.style.setProperty("--y", event.clientY + "px");
    document.body.appendChild(ripple);
    ripple.addEventListener("animationend", function () {
      ripple.remove();
    });
  });
})();
