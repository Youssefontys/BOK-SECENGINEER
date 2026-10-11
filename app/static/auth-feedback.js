"use strict";

const authFeedback = document.getElementById("auth-feedback");
if (authFeedback) {
  authFeedback.focus({ preventScroll: true });
  authFeedback.scrollIntoView({ block: "center", behavior: "auto" });
}
