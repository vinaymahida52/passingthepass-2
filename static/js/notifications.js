(function () {
  const bell = document.getElementById("notifBell");
  if (!bell) return;
  const badge = document.getElementById("notifBadge");
  const panel = document.getElementById("notifPanel");
  let lastSeenMaxId = Number(localStorage.getItem("ptp_last_notif_id") || 0);
  let desktopPermissionAsked = false;

  function render(items, unread) {
    badge.style.display = unread > 0 ? "block" : "none";
    badge.textContent = unread > 9 ? "9+" : String(unread);
    if (!items.length) {
      panel.innerHTML = '<div class="empty">No notifications yet.</div>';
      return;
    }
    panel.innerHTML = items
      .map(
        (n) => `<div class="item"><div>${n.message}</div><div class="time">${n.created_at}</div></div>`
      )
      .join("");
  }

  async function poll() {
    try {
      const res = await fetch("/api/notifications");
      if (!res.ok) return;
      const data = await res.json();
      render(data.items, data.unread);

      const newest = data.items.length ? data.items[0].id : 0;
      if (newest > lastSeenMaxId && lastSeenMaxId !== 0) {
        const fresh = data.items.filter((i) => i.id > lastSeenMaxId);
        fresh.reverse().forEach((n) => showDesktopNotification(n.message));
      }
      if (newest > 0) {
        lastSeenMaxId = newest;
        localStorage.setItem("ptp_last_notif_id", String(newest));
      }
    } catch (e) {
      /* offline - ignore */
    }
  }

  function showDesktopNotification(message) {
    if (!("Notification" in window)) return;
    if (Notification.permission === "granted") {
      new Notification("PassingThePass", { body: message, icon: "/static/img/icon.svg" });
    }
  }

  bell.addEventListener("click", async () => {
    panel.classList.toggle("open");
    if (panel.classList.contains("open")) {
      if (!desktopPermissionAsked && "Notification" in window && Notification.permission === "default") {
        desktopPermissionAsked = true;
        Notification.requestPermission();
      }
      await fetch("/api/notifications/read", { method: "POST" });
      badge.style.display = "none";
    }
  });

  document.addEventListener("click", (e) => {
    if (!panel.contains(e.target) && e.target !== bell && !bell.contains(e.target)) {
      panel.classList.remove("open");
    }
  });

  poll();
  setInterval(poll, 8000);
})();
