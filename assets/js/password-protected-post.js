(function () {
  "use strict";

  var container = document.querySelector("[data-protected-post]");
  var dataElement = document.getElementById("protected-post-data");

  if (!container || !dataElement) {
    return;
  }

  var form = container.querySelector("[data-protected-post-form]");
  var passwordInput = container.querySelector("[data-protected-post-password]");
  var submitButton = container.querySelector("[data-protected-post-submit]");
  var status = container.querySelector("[data-protected-post-status]");
  var pageTitle = document.querySelector("[data-protected-page-title]");
  var pageSubtitle = document.querySelector("[data-protected-page-subtitle]");

  function decodeBase64(value) {
    var binary = window.atob(value);
    var bytes = new Uint8Array(binary.length);

    for (var index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  }

  async function decrypt(payload, password) {
    var encoder = new TextEncoder();
    var passwordKey = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    var contentKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: decodeBase64(payload.salt),
        iterations: payload.iterations,
        hash: "SHA-256"
      },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    var plaintext = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64(payload.iv)
      },
      contentKey,
      decodeBase64(payload.ciphertext)
    );

    return new TextDecoder().decode(plaintext);
  }

  if (!window.crypto || !window.crypto.subtle) {
    status.textContent = "Your browser does not support secure local decryption.";
    passwordInput.disabled = true;
    submitButton.disabled = true;
    return;
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    if (!passwordInput.value) {
      status.textContent = "Enter a password.";
      passwordInput.focus();
      return;
    }

    submitButton.disabled = true;
    passwordInput.disabled = true;
    status.textContent = "Unlocking…";

    try {
      var payload = JSON.parse(dataElement.textContent);

      if (payload.version !== 1 && payload.version !== 2) {
        throw new Error("Unsupported encrypted article format.");
      }

      var decryptedContent = await decrypt(payload, passwordInput.value);
      var article = payload.version === 2
        ? JSON.parse(decryptedContent)
        : { html: decryptedContent };
      var publicTitle = pageTitle ? pageTitle.textContent.trim() : "";

      passwordInput.value = "";
      dataElement.remove();
      if (article.title && pageTitle) {
        pageTitle.textContent = article.title;
        document.title = document.title.replace(publicTitle, article.title);
      }
      if (article.subtitle && pageSubtitle) {
        pageSubtitle.textContent = article.subtitle;
        pageSubtitle.hidden = false;
      }
      container.classList.add("protected-post--unlocked");
      container.innerHTML = article.html;
    } catch (error) {
      status.textContent = "That password is incorrect.";
      passwordInput.value = "";
      passwordInput.disabled = false;
      submitButton.disabled = false;
      passwordInput.focus();
    }
  });
}());
