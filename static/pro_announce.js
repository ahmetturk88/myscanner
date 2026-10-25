// Pro announcement: opens once after a short delay; "Not now" hides it for 14 days, opening Pro for 60.
(function () {
  'use strict';
  var KEY = 'myscanner.proPop', DAY = 86400000;
  var dialog = document.getElementById('pro-pop');
  if (!dialog || typeof dialog.showModal !== 'function') return;
  function read() { try { return Number(localStorage.getItem(KEY)) || 0; } catch (e) { return -1; } }
  function hideFor(days) { try { localStorage.setItem(KEY, String(Date.now() + days * DAY)); } catch (e) { /* storage blocked: shown again next visit */ } }
  var until = read();
  if (until === -1 || until > Date.now()) return;  // no storage: never nag on every page
  function close(days) { hideFor(days); dialog.classList.add('closing'); setTimeout(function () { dialog.close(); dialog.classList.remove('closing'); }, 180); }
  dialog.querySelectorAll('[data-pro-dismiss]').forEach(function (b) { b.addEventListener('click', function () { close(14); }); });
  dialog.querySelector('[data-pro-go]').addEventListener('click', function () { hideFor(60); });
  dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(14); });  // Esc
  dialog.addEventListener('click', function (event) { if (event.target === dialog) close(14); });  // backdrop
  setTimeout(function () {
    if (document.querySelector('dialog[open]')) return;  // never on top of another dialog
    dialog.showModal();
    hideFor(1);  // even if the tab is closed without answering, wait a day
  }, 5000);
})();
