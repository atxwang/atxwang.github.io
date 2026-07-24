#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto").webcrypto;
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const password = process.env.POST_PASSWORD;
assert(password, "Set POST_PASSWORD to run the password-protection test.");

const siteDirectory = path.resolve("_site");
const protectedPage = findProtectedPage(siteDirectory);
const html = fs.readFileSync(protectedPage, "utf8");
const payloadMatch = html.match(
  /<script id="protected-post-data" type="application\/json">([\s\S]*?)<\/script>/
);

assert(payloadMatch, "The built site does not contain an encrypted post payload.");
assert(!html.includes("what a title amiright"), "Plaintext article content leaked into the built page.");
assert(!html.includes(password), "The password leaked into the built page.");

const payload = JSON.parse(payloadMatch[1]);

function decodeBase64(value) {
  return Buffer.from(value, "base64");
}

async function decrypt(candidatePassword) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    Buffer.from(candidatePassword, "utf8"),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const contentKey = await crypto.subtle.deriveKey(
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

  return Buffer.from(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodeBase64(payload.iv) },
      contentKey,
      decodeBase64(payload.ciphertext)
    )
  ).toString("utf8");
}

async function exerciseClientScript() {
  let submitHandler;
  const passwordInput = {
    disabled: false,
    value: "",
    focus() {}
  };
  const submitButton = { disabled: false };
  const status = { textContent: "" };
  const form = {
    addEventListener(eventName, handler) {
      assert.equal(eventName, "submit");
      submitHandler = handler;
    }
  };
  const dataElement = {
    textContent: payloadMatch[1],
    remove() {
      this.removed = true;
    }
  };
  const container = {
    classList: {
      add(className) {
        assert.equal(className, "protected-post--unlocked");
      }
    },
    innerHTML: "",
    querySelector(selector) {
      return {
        "[data-protected-post-form]": form,
        "[data-protected-post-password]": passwordInput,
        "[data-protected-post-submit]": submitButton,
        "[data-protected-post-status]": status
      }[selector];
    }
  };
  const document = {
    getElementById(id) {
      return id === "protected-post-data" ? dataElement : null;
    },
    querySelector(selector) {
      return selector === "[data-protected-post]" ? container : null;
    }
  };
  const clientScript = fs.readFileSync(
    path.resolve("assets/js/password-protected-post.js"),
    "utf8"
  );

  vm.runInNewContext(clientScript, {
    document,
    window: {
      atob(value) {
        return Buffer.from(value, "base64").toString("binary");
      },
      crypto
    },
    TextDecoder,
    TextEncoder,
    Uint8Array
  });

  assert(submitHandler, "The client script did not attach the unlock handler.");
  passwordInput.value = "definitely-the-wrong-password";
  await submitHandler({ preventDefault() {} });
  assert.equal(status.textContent, "That password is incorrect.");
  assert.equal(container.innerHTML, "");

  passwordInput.value = password;
  await submitHandler({ preventDefault() {} });
  assert(container.innerHTML.includes("what a title amiright"));
  assert.equal(dataElement.removed, true);
}

function findProtectedPage(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      const result = findProtectedPage(fullPath);
      if (result) return result;
    } else if (entry.name === "index.html") {
      const candidate = fs.readFileSync(fullPath, "utf8");
      if (candidate.includes('id="protected-post-data"')) return fullPath;
    }
  }

  return null;
}

(async function run() {
  await assert.rejects(decrypt("definitely-the-wrong-password"));
  const plaintext = await decrypt(password);
  assert(
    plaintext.includes("what a title amiright"),
    "The correct password did not recover the expected article."
  );
  await exerciseClientScript();
  console.log(`Password protection passed for ${path.relative(process.cwd(), protectedPage)}.`);
}()).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
