"use strict";

const accountMenu = document.querySelector(".account-menu");
if (accountMenu) {
  document.addEventListener("click", (event) => {
    if (!accountMenu.contains(event.target)) accountMenu.open = false;
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && accountMenu.open) {
      accountMenu.open = false;
      accountMenu.querySelector("summary").focus();
    }
  });
}
