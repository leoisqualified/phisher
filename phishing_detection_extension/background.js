chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    console.log("Message received in background:", message);

    const url = sender.tab ? sender.tab.url : message.url;
    if (!url) {
      sendResponse({ error: "No URL provided" });
      return;
    }

    // Request prediction from Flask server
    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    })
      .then((response) => {
        if (!response.ok)
          throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then((data) => {
        console.log("Response from server:", data);

        if (data.isPhishing) {
          // Redirect to warning.html using declarativeNetRequest
          chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [1],
            addRules: [
              {
                id: 1,
                priority: 1,
                action: {
                  type: "redirect",
                  redirect: { extensionPath: "/warning.html" },
                },
                condition: {
                  urlFilter: url,
                  resourceTypes: ["main_frame"],
                },
              },
            ],
          });
        } else {
          // ✅ Send a message to popup (or content script) with safe site feedback
          chrome.runtime.sendMessage({
            action: "siteSafe",
            message: "This site is safe.",
          });
        }

        sendResponse(data);
      })
      .catch((error) => {
        console.error("Error:", error);
        sendResponse({ error: "Could not connect to the server." });
      });

    return true;
  }
});

// Auto-scan on tab update
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        chrome.tabs.sendMessage(tabId, {
          action: "autoScanResult",
          url: tab.url,
          isPhishing: data.isPhishing,
        });
      })
      .catch((error) => console.error("Error checking URL:", error));
  }
});

// Show native browser alert
if (data.isPhishing) {
  chrome.action.setBadgeText({ text: "⚠️", tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId: tabId });
} else {
  chrome.action.setBadgeText({ text: "", tabId: tabId });
}
