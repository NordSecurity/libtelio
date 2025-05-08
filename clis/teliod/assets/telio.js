window.telio = {
  validateToken: input => {
    const valid = /^[0-9a-fA-F]{64}$/.test(input.value);
    if (valid) {
      input.setCustomValidity("");
    } else {
      input.setCustomValidity("Token must be a valid 64char hex number");
    }
  },

  validateTunnel: input =>  {
    const valid = /^[a-zA-Z][a-zA-Z0-9\-\.:]{0,14}$/.test(input.value);
    if (valid) {
      input.setCustomValidity("");
    } else {
      input.setCustomValidity("Must be a valid linux interface name");
    }
  },
};

// Add support to switch to dark mode based on system settings. 
document.documentElement.classList.toggle(
  "dark", window.matchMedia('(prefers-color-scheme: dark)').matches
);

