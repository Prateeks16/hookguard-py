// Playground: entirely client-side, entirely fake network-wise. Every
// scenario below is a fixed example — see the "How this simulation works"
// section on the page itself for why (this project's real correctness proof
// is the Go differential harness, not a JS crypto reimplementation).
(function () {
  var stage = document.querySelector(".playground-stage");
  if (!stage) return;

  var DATA = {
    stripe: {
      label3: "Wrong secret",
      label4: "Stale timestamp",
      body: '{"id":"evt_1NXyzAB","type":"payment_intent.succeeded"}',
      scenarios: {
        valid: { headers: ["Stripe-Signature: t=1751630400,v1=5f3a9c1e2b7d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a"], verdict: "accepted", reason: "" },
        tampered: { headers: ["Stripe-Signature: t=1751630400,v1=5f3a9c1e2b7d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a"], body: '{"id":"evt_1NXyzAB","type":"payment_intent.succeeded","amount":999999}', verdict: "rejected", reason: "signature mismatch" },
        wrong_secret: { headers: ["Stripe-Signature: t=1751630400,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], verdict: "rejected", reason: "signature mismatch" },
        edge: { headers: ["Stripe-Signature: t=1751600000,v1=5f3a9c1e2b7d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a"], verdict: "rejected", reason: "stale timestamp" }
      }
    },
    github: {
      label3: "Wrong secret",
      label4: "Malformed signature",
      body: '{"ref":"refs/heads/main"}',
      scenarios: {
        valid: { headers: ["X-Hub-Signature-256: sha256=6c1c5c3a9e2f4b7d0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f"], verdict: "accepted", reason: "" },
        tampered: { headers: ["X-Hub-Signature-256: sha256=6c1c5c3a9e2f4b7d0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f"], body: '{"ref":"refs/heads/main","force":true}', verdict: "rejected", reason: "signature mismatch" },
        wrong_secret: { headers: ["X-Hub-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000"], verdict: "rejected", reason: "signature mismatch" },
        edge: { headers: ["X-Hub-Signature-256: sha1=6c1c5c3a9e2f4b7d"], verdict: "rejected", reason: "bad encoding" }
      }
    },
    shopify: {
      label3: "Wrong secret",
      label4: "Malformed signature",
      body: '{"id":1,"financial_status":"paid"}',
      scenarios: {
        valid: { headers: ["X-Shopify-Hmac-SHA256: 2SprGmqz3hSNr0RlLQ0LlWiC0/2A0jI+f4a1n9tYtP0="], verdict: "accepted", reason: "" },
        tampered: { headers: ["X-Shopify-Hmac-SHA256: 2SprGmqz3hSNr0RlLQ0LlWiC0/2A0jI+f4a1n9tYtP0="], body: '{"id":1,"financial_status":"refunded"}', verdict: "rejected", reason: "signature mismatch" },
        wrong_secret: { headers: ["X-Shopify-Hmac-SHA256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="], verdict: "rejected", reason: "signature mismatch" },
        edge: { headers: ["X-Shopify-Hmac-SHA256: not-base64-!!!"], verdict: "rejected", reason: "bad encoding" }
      }
    },
    paypal: {
      label3: "Forged signature",
      label4: "Forged cert host",
      body: '{"event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"CAP-123"}}',
      scenarios: {
        valid: {
          headers: ["paypal-transmission-id: 7b1e2f3a-201f-4c0e-9a1e-2f3a7b1e2f3a", "paypal-transmission-time: 2026-07-04T12:00:00Z", "paypal-cert-url: https://api.paypal.com/v1/notifications/certs/CERT-abc123", "paypal-auth-algo: SHA256withRSA", "paypal-transmission-sig: (RSA-SHA256, base64, 344 bytes)"],
          verdict: "accepted", reason: ""
        },
        tampered: {
          headers: ["paypal-transmission-id: 7b1e2f3a-201f-4c0e-9a1e-2f3a7b1e2f3a", "paypal-transmission-time: 2026-07-04T12:00:00Z", "paypal-cert-url: https://api.paypal.com/v1/notifications/certs/CERT-abc123", "paypal-auth-algo: SHA256withRSA", "paypal-transmission-sig: (RSA-SHA256, base64, 344 bytes)"],
          body: '{"event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"CAP-999"}}',
          verdict: "rejected", reason: "signature mismatch"
        },
        wrong_secret: {
          headers: ["paypal-transmission-id: 7b1e2f3a-201f-4c0e-9a1e-2f3a7b1e2f3a", "paypal-transmission-time: 2026-07-04T12:00:00Z", "paypal-cert-url: https://api.paypal.com/v1/notifications/certs/CERT-abc123", "paypal-auth-algo: SHA256withRSA", "paypal-transmission-sig: (forged, does not match the real cert)"],
          verdict: "rejected", reason: "signature mismatch"
        },
        edge: {
          headers: ["paypal-transmission-id: 7b1e2f3a-201f-4c0e-9a1e-2f3a7b1e2f3a", "paypal-transmission-time: 2026-07-04T12:00:00Z", "paypal-cert-url: https://evil.com/fake-cert.pem", "paypal-auth-algo: SHA256withRSA", "paypal-transmission-sig: (RSA-SHA256, base64, 344 bytes)"],
          verdict: "rejected", reason: "cert host rejected"
        }
      }
    }
  };

  var providerBtns = document.querySelectorAll("[data-provider]");
  var scenarioBtns = document.querySelectorAll("[data-scenario]");
  var edgeBtn = document.getElementById("pg-edge-btn");
  var wrongSecretBtn = document.querySelector('[data-scenario="wrong_secret"]');
  var requestEl = document.getElementById("pg-request");
  var stageProvider = document.getElementById("pg-stage-provider");
  var envelope = document.getElementById("pg-envelope");
  var envMark = document.getElementById("pg-env-mark");
  var verdictEl = document.getElementById("pg-verdict");
  var sendBtn = document.getElementById("pg-send");

  var provider = "stripe";
  var scenario = "valid";

  function setPressed(list, matchAttr, value) {
    list.forEach(function (el) {
      el.setAttribute("aria-pressed", el.getAttribute(matchAttr) === value ? "true" : "false");
    });
  }

  function render() {
    var p = DATA[provider];
    var s = p.scenarios[scenario];
    edgeBtn.textContent = p.label4;
    wrongSecretBtn.textContent = p.label3;
    stageProvider.textContent = provider.charAt(0).toUpperCase() + provider.slice(1);

    var body = s.body || p.body;
    var lines = ["POST /hook/" + provider + " HTTP/1.1"].concat(s.headers).concat(["", body]);
    requestEl.textContent = lines.join("\n");

    envelope.classList.remove("pg-armed", "pg-accepted", "pg-rejected");
    envMark.textContent = "";
    verdictEl.innerHTML = "";
  }

  providerBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      provider = btn.getAttribute("data-provider");
      scenario = "valid";
      setPressed(providerBtns, "data-provider", provider);
      setPressed(scenarioBtns, "data-scenario", scenario);
      render();
    });
  });

  scenarioBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      scenario = btn.getAttribute("data-scenario");
      setPressed(scenarioBtns, "data-scenario", scenario);
      render();
    });
  });

  sendBtn.addEventListener("click", function () {
    var s = DATA[provider].scenarios[scenario];
    envelope.classList.remove("pg-accepted", "pg-rejected");
    envMark.textContent = "";
    verdictEl.innerHTML = "";
    // Force reflow so re-triggering the same scenario twice still animates.
    void envelope.offsetWidth;
    envelope.classList.add("pg-armed");

    var duration = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--playground-travel")) || 900;
    if (s.verdict === "accepted") {
      envelope.classList.add("pg-accepted");
      setTimeout(function () {
        envMark.textContent = "✓";
        verdictEl.innerHTML = '<span class="verdict-ok">&#10003; accepted</span> — forwarded to your app.';
      }, duration);
    } else {
      envelope.classList.add("pg-rejected");
      setTimeout(function () {
        envMark.textContent = "✗";
        verdictEl.innerHTML = '<span class="verdict-reject">&#10007; rejected (401)</span> — reason: <code>' + s.reason + "</code>";
      }, duration);
    }
  });

  render();
})();
