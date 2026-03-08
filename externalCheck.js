const whois = require("whois-json");

async function checkDomainAge(domain) {

  try {

    const data = await whois(domain);

    if (data.creationDate) {

      const creation = Array.isArray(data.creationDate)
        ? data.creationDate[0]
        : data.creationDate;

      const created = new Date(creation);
      const now = new Date();

      const ageDays = (now - created) / (1000 * 60 * 60 * 24);

      return ageDays;

    }

    return null;

  } catch (err) {

    return null;

  }

}

module.exports = checkDomainAge;