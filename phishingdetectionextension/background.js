chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    console.log("Message received in background:", message);

    // Send a request to the Flask server
    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Response from server:", data);
        sendResponse(data);
      })
      .catch((error) => {
        console.error("Error:", error);
        sendResponse({ error: "Could not connect to the server." });
      });

    // Keep the message channel open for async responses
    return true;
  }
});
