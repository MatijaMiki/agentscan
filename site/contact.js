/* Composes a mailto: from the form. There is no backend and no third party:
   the message only ever exists in the visitor's own mail client until they
   choose to send it. Degrades to the plain address if anything here fails. */
(function () {
  "use strict";
  var form = document.getElementById("contact-form");
  if (!form) return;

  var SUBJECTS = {
    team: "ranwhat Team",
    evidence: "ranwhat Evidence",
    bug: "ranwhat: something the tool got wrong",
    other: "ranwhat"
  };

  /* Let a link carry the topic in, so "Start a trial" lands on the right one. */
  try {
    var wanted = new URLSearchParams(location.search).get("about");
    var about = document.getElementById("about");
    if (wanted && about && SUBJECTS.hasOwnProperty(wanted)) about.value = wanted;
  } catch (e) { /* no URLSearchParams, or a blocked location: keep the default */ }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();

    var topic = (document.getElementById("about") || {}).value || "other";
    var agents = ((document.getElementById("agents") || {}).value || "").trim();
    var message = ((document.getElementById("message") || {}).value || "").trim();
    var note = document.getElementById("form-note");

    if (!message) {
      if (note) note.textContent = "Add a message first, then this will open your mail app.";
      var box = document.getElementById("message");
      if (box) box.focus();
      return;
    }

    var body = message;
    if (agents) body += "\n\n---\nAgents: " + agents;

    var href = "mailto:hello@ranwhat.com"
      + "?subject=" + encodeURIComponent(SUBJECTS[topic] || SUBJECTS.other)
      + "&body=" + encodeURIComponent(body);

    /* Some clients truncate very long mailto URLs; say so rather than
       silently losing the tail of someone's message. */
    if (href.length > 1900 && note) {
      note.textContent = "That is long enough that some mail apps will cut it. "
        + "Consider writing to hello@ranwhat.com directly.";
    }

    location.href = href;
  });
})();
