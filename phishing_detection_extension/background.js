chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    console.log("Message received in background:", message);

    const url = sender.tab ? sender.tab.url : message.url;
    if (!url) {
      sendResponse({ error: "No URL provided" });
      return;
    }

    chrome.storage.local.get(["companyApiKey"], (result) => {
      const apikey = result.companyApiKey;
      if (!apikey) {
        console.warn("No API key set. Aborting request.");
        sendResponse({ error: "API key missing." });
        return;
      }

      fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-KEY": apikey,
        },
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
    });

    return true; // Keep message channel open for async response
  }
});

// ✅ Auto-scan logic when tabs are updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  chrome.storage.local.get(["companyApiKey"], (result) => {
    const apikey = result.companyApiKey;
    if (!apikey) {
      console.warn("No API key set. Skipping auto scan.");
      return;
    }

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": apikey,
      },
      body: JSON.stringify({ url: tab.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Auto-scan result:", data);

        chrome.tabs.sendMessage(tabId, {
          action: "autoScanResult",
          url: tab.url,
          isPhishing: data.isPhishing,
        });

        // Set badge
        chrome.action.setBadgeText({
          text: data.isPhishing ? "⚠️" : "",
          tabId: tabId,
        });

        if (data.isPhishing) {
          chrome.action.setBadgeBackgroundColor({
            color: "#FF0000",
            tabId: tabId,
          });
        }
      })
      .catch((error) => {
        console.error("Auto scan failed:", error);
      });
  });
});
