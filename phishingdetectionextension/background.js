chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    const url = message.url;

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: url }),
    })
      .then((response) => response.json())
      .then((data) => {
        sendResponse(data); // Ensure this sends back a response
      })
      .catch((error) => {
        console.error("Error fetching prediction:", error);
        sendResponse({ error: "Failed to fetch prediction" });
      });

    return true; // Keeps the message channel open for async responses
  } else {
    sendResponse({ error: "Invalid action" });
  }
});
