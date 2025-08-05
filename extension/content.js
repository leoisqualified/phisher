// Get the current page URL
const url = window.location.href;

// Send message to background script to check phishing
chrome.runtime.sendMessage(
  { action: "checkPhishing", url: url },
  (response) => {
    if (chrome.runtime.lastError) {
      console.error("Runtime error:", chrome.runtime.lastError.message);
      return;
    }

    if (response && response.prediction === "Phishing") {
      console.warn("Phishing site detected:", url);

      // Optional blocking (can be turned on/off via settings)
      const blockSite = true; // Set this dynamically based on user preferences
      if (blockSite) {
        document.body.innerHTML = `<h1 style="color:red; text-align:center; margin-top:20%;">⚠️ Warning: This website is flagged as phishing! ⚠️</h1>`;
      } else {
        alert("⚠️ Warning: This website is flagged as phishing!");
      }
    }
  }
);
