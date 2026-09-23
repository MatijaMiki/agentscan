/* Posts the form to /api/contact, which verifies the Turnstile token before
 * sending anything. Everything here is convenience: the checks that matter run
 * on the server, because anything in this file can be edited by whoever is
 * looking at the page.
 */
(function () {
  "use strict";
  var form = document.getElementById("contact-form");
  if (!form) return;

  var note = document.getElementById("form-note");
  var button = document.getElementById("send");
  var RESTING = note ? note.textContent : "";

  /* Let a link carry the topic in, so "Start a trial" lands on the right one. */
  try {
    var wanted = new URLSearchParams(location.search).get("about");
    var about = document.getElementById("about");
    if (wanted && about && about.querySelector('option[value="' + wanted + '"]')) {
      about.value = wanted;
    }
  } catch (e) { /* keep the default */ }

  function say(text) { if (note) note.textContent = text; }

  function busy(on) {
    if (!button) return;
    button.disabled = on;
    button.textContent = on ? "Sending…" : "Send →";
  }

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();

    var payload = {
      about: (document.getElementById("about") || {}).value || "other",
      email: ((document.getElementById("email") || {}).value || "").trim(),
      agents: ((document.getElementById("agents") || {}).value || "").trim(),
      message: ((document.getElementById("message") || {}).value || "").trim(),
      "cf-turnstile-response": (form.querySelector('[name="cf-turnstile-response"]') || {}).value,
    };

    if (!payload.message) { say("Add a message first."); return; }
    if (!payload.email) { say("Add an email so we can reply."); return; }
    if (!payload["cf-turnstile-response"]) {
      say("Wait for the challenge to finish, then send.");
      return;
    }

    busy(true);
    say("Sending…");
    try {
      var res = await fetch("/api/contact", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      var data = await res.json().catch(function () { return {}; });

      if (res.ok && data.ok) {
        form.innerHTML =
          '<p class="sent">Sent. We read everything, and a day or two is a ' +
          'normal reply time.</p>';
        return;
      }
      say(data.error || "That did not send. Write to hello@ranwhat.com instead.");
    } catch (e) {
      say("That did not send, which may be the network. Write to hello@ranwhat.com instead.");
    } finally {
      busy(false);
      /* A used token is not accepted twice, so get a fresh one for a retry. */
      if (window.turnstile) { try { window.turnstile.reset(); } catch (e) {} }
    }
  });

  form.addEventListener("input", function () {
    if (note && note.textContent !== RESTING) say(RESTING);
  });
})();
