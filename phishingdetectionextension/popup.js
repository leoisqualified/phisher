document.addEventListener("DOMContentLoaded", () => {
  const checkButton = document.getElementById("checkPhishing");
  const resultContainer = document.getElementById("result");

  checkButton.addEventListener("click", () => {
    // Get the URL of the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      const url = activeTab.url;

      console.log("Active tab URL:", url);

      // Send the URL to the background script
      chrome.runtime.sendMessage(
        { action: "checkPhishing", url: url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error("Runtime error:", chrome.runtime.lastError.message);
            resultContainer.textContent = "Error: Could not determine.";
          } else if (response.error) {
            console.error("Response error:", response.error);
            resultContainer.textContent = response.error;
          } else {
            resultContainer.textContent = response.isPhishing
              ? "This site is a phishing website."
              : "This site is safe.";
          }
        }
      );
    });
  });
});
