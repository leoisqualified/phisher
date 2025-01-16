chrome.runtime.sendMessage(
  { action: "checkPhishing", url: window.location.href },
  (response) => {
    if (response.error) {
      console.error("Error:", response.error);
    } else {
      console.log("Phishing Detection Result:", response);
    }
  }
);
