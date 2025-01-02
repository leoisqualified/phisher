// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "detectPhishing") {
    const url = request.url;
    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(data => sendResponse(data))
    .catch(error => {
      console.error("Error:", error);
      sendResponse({ error: "Unable to fetch prediction." });
    });
    return true; // Keep the messaging channel open for async response
  }
});
