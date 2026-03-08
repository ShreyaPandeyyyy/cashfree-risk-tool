const express = require("express");
const cors = require("cors");

const crawlWebsite = require("./crawler");
const riskRules = require("./riskRules");
const riskScore = require("./riskScore");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

app.post("/analyze", async (req, res) => {

  try {

    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL required" });
    }

    const crawlData = await crawlWebsite(url);

    console.log("CRAWL DATA:", crawlData);

    const rules = riskRules(crawlData);

    const score = riskScore(rules);

    res.json({
      url: url,

      emails: crawlData.emails || [],
      phones: crawlData.phones || [],
      totalLinks: crawlData.totalLinks || 0,
      externalLinks: crawlData.externalLinks || 0,

      loginForms: crawlData.loginForms || 0,
      paymentSignals: crawlData.paymentSignals || 0,
      suspiciousSignals: crawlData.suspiciousSignals || 0,

      hiddenElements: crawlData.hiddenElements || 0,
      iframeCount: crawlData.iframeCount || 0,

      domainAgeDays: crawlData.domainAgeDays || null,
      suspiciousTLD: crawlData.suspiciousTLD || false,

      rules: rules,

      riskScore: score.riskScore,
      trustScore: score.trustScore,
      riskLevel: score.riskLevel
    });

  } catch (err) {

    console.error("ANALYZE ERROR:", err);

    res.json({
      url: req.body.url,
      emails: [],
      phones: [],
      totalLinks: 0,
      externalLinks: 0,
      loginForms: 0,
      paymentSignals: 0,
      suspiciousSignals: 0,
      hiddenElements: 0,
      iframeCount: 0,
      domainAgeDays: null,
      suspiciousTLD: false,
      rules: [],
      riskScore: 0,
      trustScore: 0,
      riskLevel: "Unknown"
    });

  }

});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});