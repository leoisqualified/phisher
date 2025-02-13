chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    const url = window.location.href;

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: url }),
    })
      .then((response) => response.json())
      .then((data) => {
        sendResponse({ isPhishing: data.prediction === "Phishing" });
      })
      .catch((error) => {
        console.error("Fetch error:", error);
        sendResponse({ error: "Failed to fetch prediction." });
      });

    return true; // Keeps the response channel open for async operations
  }
});
