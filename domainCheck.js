const whois = require("whois-json");

async function checkDomain(domain) {
  try {
    const data = await whois(domain);
    const risks = [];

    // -----------------------------
    // Normalize WHOIS fields
    // -----------------------------

    const creationDate =
      data.creationDate ||
      data.created ||
      data["Creation Date"] ||
      data.createdDate;

    const expiryDate =
      data.registrarRegistrationExpirationDate ||
      data.expiryDate ||
      data["Registry Expiry Date"] ||
      data.expires;

    const registrar = (data.registrar || "").toLowerCase();
    const whoisText = JSON.stringify(data).toLowerCase();

    // -----------------------------
    // DOMAIN AGE CHECK
    // -----------------------------

    if (creationDate) {
      const creationValue = Array.isArray(creationDate)
        ? creationDate[0]
        : creationDate;

      const created = new Date(creationValue);

      if (!isNaN(created)) {
        const now = new Date();

        const ageDays = Math.floor(
          (now - created) / (1000 * 60 * 60 * 24)
        );

        if (ageDays < 30) {
          risks.push({
            element: "Domain Age",
            category: "Domain Intelligence",
            rule: "Very new domain detected",
            severity: "High",
            reason:
              "Fraud websites are often created very recently"
          });

        } else if (ageDays < 180) {
          risks.push({
            element: "Domain Age",
            category: "Domain Intelligence",
            rule: "Recently created domain",
            severity: "Medium",
            reason:
              "New domains often have higher fraud risk"
          });
        }
      }
    }

    // -----------------------------
    // DOMAIN EXPIRY CHECK
    // -----------------------------

    if (expiryDate) {
      const expiryValue = Array.isArray(expiryDate)
        ? expiryDate[0]
        : expiryDate;

      const expiry = new Date(expiryValue);

      if (!isNaN(expiry)) {
        const now = new Date();

        const remainingDays = Math.floor(
          (expiry - now) / (1000 * 60 * 60 * 24)
        );

        if (remainingDays < 90) {
          risks.push({
            element: "Domain Expiry",
            category: "Domain Intelligence",
            rule: "Domain expiring soon",
            severity: "Medium",
            reason:
              "Fraud domains are often registered for short durations"
          });
        }
      }
    }

    // -----------------------------
    // CHEAP REGISTRAR DETECTION
    // -----------------------------

    const cheapRegistrars = [
      "namecheap",
      "godaddy",
      "dynadot",
      "namesilo",
      "hostinger"
    ];

    cheapRegistrars.forEach(r => {
      if (registrar.includes(r)) {
        risks.push({
          element: "Domain Registrar",
          category: "Domain Intelligence",
          rule: "Low-cost registrar used",
          severity: "Low",
          reason:
            "Fraud sites often use low-cost registrars"
        });
      }
    });

    // -----------------------------
    // WHOIS PRIVACY CHECK
    // -----------------------------

    if (
      whoisText.includes("privacy") ||
      whoisText.includes("redacted") ||
      whoisText.includes("whoisguard")
    ) {
      risks.push({
        element: "WHOIS Privacy",
        category: "Domain Intelligence",
        rule: "WHOIS ownership hidden",
        severity: "Low",
        reason:
          "Fraud websites frequently hide registrant identity"
      });
    }

    return risks;

  } catch (err) {
    console.log("Domain check failed:", err.message);
    return [];
  }
}

module.exports = checkDomain;

