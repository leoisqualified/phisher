chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "detectPhishing") {
    console.log("Received URL:", request.url); // Log URL sent by the extension

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: request.url }),
    })
      .then((response) => {
        console.log("Server Response Status:", response.status); // Log server status
        if (!response.ok) {
          throw new Error(`Server error: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        console.log("Prediction Result:", data); // Log server response
        sendResponse(data);
      })
      .catch((error) => {
        console.error("Error fetching prediction:", error);
        sendResponse({ error: "Unable to fetch prediction." });
      });

    return true;
  }
});
