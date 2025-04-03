chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    console.log("Message received in background:", message);

    // Ensure we get the correct URL from sender tab
    const url = sender.tab ? sender.tab.url : message.url;
    if (!url) {
      sendResponse({ error: "No URL provided" });
      return;
    }

    // Send a request to the Flask server
    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    })
      .then((response) => {
        if (!response.ok)
          throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then((data) => {
        console.log("Response from server:", data);
        if (data.isPhishing) {
          chrome.tabs.update(sender.tab.id, { url: "warning.html" });
        } else {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: "Phishing Detector",
            message: "This site is safe.",
          });
        }
        sendResponse(data);
      })
      .catch((error) => {
        console.error("Error:", error);
        sendResponse({ error: "Could not connect to the server." });
      });

    return true; // Keeps the message channel open for async response
  }
});

// Automatically scan URLs when a new tab is opened or updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    chrome.runtime.sendMessage({ action: "checkPhishing", url: tab.url });
  }
});
